// Place at the ROOT of the target portal project (next to index.html).
// Env vars (target portal project):
//   LICENSE_API     https://YOUR-LICENSE-APP.vercel.app/api/verify
//   VERIFY_SECRET   same value as in the license app
//   LICENSE_SECRET  any long random string (signs the cookie)

const TTL = 600; // seconds a valid check is trusted before re-verifying (revocation delay)
const enc = new TextEncoder();

const next = () => new Response(null, { headers: { 'x-middleware-next': '1' } });

async function sign(s) {
  const k = await crypto.subtle.importKey('raw', enc.encode(process.env.LICENSE_SECRET),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const b = await crypto.subtle.sign('HMAC', k, enc.encode(s));
  return [...new Uint8Array(b)].map(x => x.toString(16).padStart(2, '0')).join('');
}

// true = valid, false = rejected, null = license server unreachable
async function check(key, host) {
  try {
    const r = await fetch(process.env.LICENSE_API, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-verify-secret': process.env.VERIFY_SECRET },
      body: JSON.stringify({ key, host })
    });
    if (!r.ok) return null;
    return (await r.json()).valid === true;
  } catch (e) { return null; }
}

async function cookieFor(key) {
  const exp = Math.floor(Date.now() / 1000) + TTL;
  return key + '.' + exp + '.' + await sign(key + '.' + exp);
}
const setCookie = v => 'lic=' + v + '; Path=/; Max-Age=2592000; HttpOnly; Secure; SameSite=Lax';
const clearCookie = 'lic=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax';

function gate(msg, clear) {
  const esc = s => s.replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
  const html = '<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">' +
    '<meta name="viewport" content="width=device-width,initial-scale=1"><title>License required</title>' +
    '<style>:root{--bg:#e8e4dc;--tx:#3a3732;--s1:#fff9;--s2:#b9b3a755}' +
    '@media(prefers-color-scheme:dark){:root{--bg:#2a2926;--tx:#e6e1d6;--s1:#3a3935;--s2:#161513}}' +
    'body{margin:0;min-height:100vh;display:grid;place-items:center;background:var(--bg);color:var(--tx);font:15px system-ui,sans-serif}' +
    'form{width:min(360px,90vw);padding:26px;border-radius:18px;box-shadow:7px 7px 14px var(--s2),-7px -7px 14px var(--s1)}' +
    'h1{font-size:20px;margin:0 0 6px}p{margin:0 0 14px;opacity:.7;font-size:13px}' +
    'input{width:100%;box-sizing:border-box;padding:11px 14px;border:0;border-radius:12px;background:var(--bg);color:var(--tx);font:inherit;' +
    'box-shadow:inset 4px 4px 8px var(--s2),inset -4px -4px 8px var(--s1)}' +
    'button{width:100%;margin-top:14px;padding:10px;border:0;border-radius:12px;background:var(--bg);color:var(--tx);font:inherit;font-weight:600;cursor:pointer;' +
    'box-shadow:4px 4px 8px var(--s2),-4px -4px 8px var(--s1)}.e{color:#c0463d;opacity:1}</style></head><body>' +
    '<form method="POST" action="/__license"><h1>Enter your license key</h1>' +
    '<p class="e">' + esc(msg || '') + '</p>' +
    '<input name="key" placeholder="LIC-XXXX-XXXX-XXXX-XXXX" autocomplete="off" required autofocus>' +
    '<button type="submit">Unlock</button></form></body></html>';
  const h = { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' };
  if (clear) h['Set-Cookie'] = clearCookie;
  return new Response(html, { status: 401, headers: h });
}

export default async function middleware(req) {
  const url = new URL(req.url);
  const host = url.host;

  // Key submitted from the gate page
  if (url.pathname === '/__license' && req.method === 'POST') {
    const key = String((await req.formData()).get('key') || '').trim().toUpperCase();
    const ok = await check(key, host);
    if (ok === true) {
      return new Response(null, { status: 303, headers: { Location: '/', 'Set-Cookie': setCookie(await cookieFor(key)) } });
    }
    return gate(ok === null ? 'License server unreachable. Try again shortly.' : 'This key is not valid for this site.');
  }

  // Existing session cookie
  const m = (req.headers.get('cookie') || '').match(/(?:^|;\s*)lic=([^;]+)/);
  if (m) {
    const [key, exp, sig] = m[1].split('.');
    if (key && exp && sig && sig === await sign(key + '.' + exp)) {
      if (+exp > Math.floor(Date.now() / 1000)) return next();     // still fresh
      const ok = await check(key, host);                            // stale: re-verify
      if (ok === null) return next();                               // license server down: grace
      if (ok === true) {
        if (req.method !== 'GET') return next();
        return new Response(null, { status: 307, headers: { Location: req.url, 'Set-Cookie': setCookie(await cookieFor(key)) } });
      }
      return gate('This license was revoked or has expired.', true);
    }
  }
  return gate('');
}

export const config = { matcher: '/((?!_vercel|favicon.ico).*)' };
