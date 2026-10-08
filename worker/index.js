// Cloudflare Worker. Secrets: GITHUB_TOKEN, APPROVAL_PIN, WEBHOOK_KEY, TWILIO_ACCOUNT_SID (TWILIO_AUTH_TOKEN optional).
const esc = s => String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&apos;' }[c]));
const say = t => `<Say language="en-US">${esc(t)}</Say>`;
const xml = inner => new Response(`<?xml version="1.0" encoding="UTF-8"?><Response>${inner}</Response>`, { headers: { 'Content-Type': 'text/xml' } });

// Trial Twilio accounts may send no X-Twilio-Signature header, so we authenticate with a shared
// key in the URL (WEBHOOK_KEY) plus the expected AccountSid. If a signature is present it must be valid.
const safeEq = (a, b) => {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return d === 0;
};

async function signatureOk(request, url, params, authToken) {
  const got = request.headers.get('X-Twilio-Signature');
  if (!got) return true; // not sent (trial accounts); key check below is the gate
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(authToken.trim()), { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
  const u = new URL(url);
  const reencoded = `${u.origin}${u.pathname}?${new URLSearchParams(u.searchParams).toString()}`;
  for (const c of new Set([url, reencoded, decodeURIComponent(url)])) {
    const data = c + Object.keys(params).sort().map(k => k + params[k]).join('');
    const sig = new Uint8Array(await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(data)));
    if (btoa(String.fromCharCode(...sig)) === got) return true;
  }
  return false;
}

export default {
  async fetch(request, env) {
    if (request.method !== 'POST') return new Response('PR phone approver running');
    const url = new URL(request.url);
    const form = Object.fromEntries(new URLSearchParams(await request.text()));
    if (!env.WEBHOOK_KEY || !env.TWILIO_ACCOUNT_SID) { console.log('missing secret WEBHOOK_KEY or TWILIO_ACCOUNT_SID'); return new Response('misconfigured', { status: 500 }); }
    if (!safeEq(url.searchParams.get('k') || '', env.WEBHOOK_KEY) || !safeEq(form.AccountSid || '', env.TWILIO_ACCOUNT_SID)) {
      return new Response('forbidden', { status: 403 });
    }
    if (env.TWILIO_AUTH_TOKEN && !(await signatureOk(request, request.url, form, env.TWILIO_AUTH_TOKEN))) {
      return new Response('forbidden', { status: 403 });
    }

    const step = url.searchParams.get('step') || 'voice';
    const repo = url.searchParams.get('repo');
    const pr = url.searchParams.get('pr');
    const sha = url.searchParams.get('sha');
    const qs = s => `${url.origin}${url.pathname}?step=${s}&amp;repo=${encodeURIComponent(repo)}&amp;pr=${pr}&amp;sha=${sha}&amp;k=${encodeURIComponent(url.searchParams.get('k'))}`;

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
        say(`Hello Nay. Pull request number ${pr} in repository ${repo.replace('/', ' slash ')} is ready. All checks passed. ` +
          `Author ${p.user?.login || 'unknown'}. Title: ${p.title || 'no title'}. ` +
          `${p.changed_files ?? 0} files changed, ${p.additions ?? 0} additions, ${p.deletions ?? 0} deletions. ` +
          `Press 1 to approve and merge. Press 2 to reject and close. Press 3 to hear this again.`) +
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
