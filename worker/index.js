// Cloudflare Worker. Secrets: GITHUB_TOKEN, APPROVAL_PIN, TWILIO_AUTH_TOKEN.
const esc = s => String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&apos;' }[c]));
const say = t => `<Say voice="Polly.Joanna">${esc(t)}</Say>`;
const xml = inner => new Response(`<?xml version="1.0" encoding="UTF-8"?><Response>${inner}</Response>`, { headers: { 'Content-Type': 'text/xml' } });

async function validTwilio(request, url, params, authToken) {
  const data = url + Object.keys(params).sort().map(k => k + params[k]).join('');
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(authToken), { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
  const sig = new Uint8Array(await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(data)));
  const expected = btoa(String.fromCharCode(...sig));
  return expected === request.headers.get('X-Twilio-Signature');
}

export default {
  async fetch(request, env) {
    if (request.method !== 'POST') return new Response('PR phone approver running');
    const url = new URL(request.url);
    const form = Object.fromEntries(new URLSearchParams(await request.text()));
    if (!(await validTwilio(request, request.url, form, env.TWILIO_AUTH_TOKEN))) return new Response('forbidden', { status: 403 });

    const step = url.searchParams.get('step') || 'voice';
    const repo = url.searchParams.get('repo');
    const pr = url.searchParams.get('pr');
    const sha = url.searchParams.get('sha');
    const qs = s => `${url.origin}${url.pathname}?step=${s}&amp;repo=${encodeURIComponent(repo)}&amp;pr=${pr}&amp;sha=${sha}`;

    const gh = async (path, opts = {}) => {
      const r = await fetch(`https://api.github.com${path}`, {
        ...opts,
        headers: { Authorization: `Bearer ${env.GITHUB_TOKEN}`, Accept: 'application/vnd.github+json', 'User-Agent': 'pr-phone-approver' },
      });
      return { ok: r.ok, data: await r.json().catch(() => ({})) };
    };

    if (step === 'voice') {
      const { data: p } = await gh(`/repos/${repo}/pulls/${pr}`);
      return xml(
        `<Gather numDigits="1" action="${qs('decision')}" timeout="8">` +
        say(`Pull request ${pr} in ${repo.split('/')[1]} is ready. All checks passed. From ${p.user?.login}. ${p.title}. ` +
          `${p.changed_files} files changed, ${p.additions} additions, ${p.deletions} deletions. ` +
          `Press 1 to merge. Press 2 to deny and close. Press 3 to hear this again.`) +
        `</Gather>` + say('No input received. Goodbye.'));
    }

    if (step === 'decision') {
      const d = form.Digits;
      if (d === '3') return xml(`<Redirect method="POST">${qs('voice')}</Redirect>`);
      if (d === '1') {
        return xml(`<Gather numDigits="${env.APPROVAL_PIN.length}" action="${qs('confirm')}" timeout="8">` +
          say('Enter your PIN to confirm the merge.') + `</Gather>` + say('No PIN entered. Goodbye.'));
      }
      if (d === '2') {
        await gh(`/repos/${repo}/issues/${pr}/comments`, { method: 'POST', body: JSON.stringify({ body: 'Denied by phone approval.' }) });
        await gh(`/repos/${repo}/pulls/${pr}`, { method: 'PATCH', body: JSON.stringify({ state: 'closed' }) });
        return xml(say('Pull request closed.'));
      }
      return xml(say('Invalid choice.') + `<Redirect method="POST">${qs('voice')}</Redirect>`);
    }

    if (step === 'confirm') {
      if (form.Digits !== env.APPROVAL_PIN) return xml(say('Wrong PIN. Request cancelled.'));
      const { data: p } = await gh(`/repos/${repo}/pulls/${pr}`);
      if (p.state !== 'open') return xml(say('This pull request is no longer open.'));
      if (p.head.sha !== sha) return xml(say('New commits were pushed since the checks passed. Merge cancelled.'));
      const m = await gh(`/repos/${repo}/pulls/${pr}/merge`, {
        method: 'PUT', body: JSON.stringify({ sha, merge_method: env.MERGE_METHOD || 'squash' }),
      });
      return xml(say(m.ok ? 'Merged. Goodbye.' : `Merge failed. ${m.data.message || ''}`));
    }

    return xml(say('Unknown step.'));
  },
};
