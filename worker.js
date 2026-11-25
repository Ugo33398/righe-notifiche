/* Righe — servizio notifiche (Cloudflare Worker, piano gratuito).
   Riceve dall'app l'elenco dei promemoria con la loro ora; ogni minuto controlla quali sono scaduti e manda
   una notifica push al telefono (anche ad app chiusa). Il testo passa da qui solo per essere mostrato. */

const enc = new TextEncoder();
const b64u = (buf) => { let s = ''; new Uint8Array(buf).forEach((c) => { s += String.fromCharCode(c); }); return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); };
const CORS = { 'access-control-allow-origin': '*', 'access-control-allow-headers': 'content-type', 'access-control-allow-methods': 'GET,POST,OPTIONS', 'cache-control': 'no-store' };
const json = (o, status) => new Response(JSON.stringify(o), { status: status || 200, headers: Object.assign({ 'content-type': 'application/json' }, CORS) });
const getJ = async (env, k, d) => { const v = await env.KV.get(k, 'json'); return v == null ? d : v; };
const putJ = (env, k, v) => env.KV.put(k, JSON.stringify(v));

async function newConfig() {
  const kp = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const jwk = await crypto.subtle.exportKey('jwk', kp.privateKey);
  const pub = b64u(await crypto.subtle.exportKey('raw', kp.publicKey));
  const key = b64u(crypto.getRandomValues(new Uint8Array(24)));
  return { key, pub, jwk };
}

async function vapidHeader(cfg, endpoint) {
  const head = b64u(enc.encode(JSON.stringify({ typ: 'JWT', alg: 'ES256' })));
  const body = b64u(enc.encode(JSON.stringify({ aud: new URL(endpoint).origin, exp: Math.floor(Date.now() / 1000) + 12 * 3600, sub: 'https://ugo33398.github.io/Righe/' })));
  const k = await crypto.subtle.importKey('jwk', cfg.jwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, k, enc.encode(head + '.' + body));
  return 'vapid t=' + head + '.' + body + '.' + b64u(sig) + ', k=' + cfg.pub;
}

// notifica «vuota»: il telefono si sveglia e l'app (service worker) chiede qui il testo da mostrare
async function sendPush(cfg, sub) {
  const r = await fetch(sub.endpoint, { method: 'POST', headers: { TTL: '3600', Urgency: 'high', Authorization: await vapidHeader(cfg, sub.endpoint), 'Content-Length': '0' } });
  return r.status;
}

async function authed(env, key) { const cfg = await getJ(env, 'cfg', null); return cfg && key && key === cfg.key ? cfg : null; }

async function tick(env, force) {
  const cfg = await getJ(env, 'cfg', null); if (!cfg) return;
  const devs = await getJ(env, 'devs', {}), run = await getJ(env, 'run', { sent: {}, pend: {} });
  const now = Date.now(); let changed = false, gone = false;
  const live = {};
  for (const dev in devs) {
    const d = devs[dev]; if (!d.sub) continue;
    const fresh = [];
    for (const it of d.items || []) {
      const k = dev + '|' + it.i + '|' + it.at; live[k] = 1;
      const last = run.sent[k];
      let due = false;
      if (it.at <= now) {
        if (last === undefined) due = it.rep > 0 || now - it.at < 6 * 3600000;
        else if (last > 0 && it.rep > 0 && now - last >= it.rep * 60000) due = true;
        if (last === undefined && !due) { run.sent[k] = -1; changed = true; }
      }
      if (due) fresh.push({ k, i: it.i, t: it.t || 'Promemoria', b: it.b || '' });
    }
    if (!fresh.length) continue;
    const st = await sendPush(cfg, d.sub).catch(() => 0);
    if (st >= 200 && st < 300) {
      fresh.forEach((f) => { run.sent[f.k] = now; });
      const old = (run.pend[dev] || []).filter((p) => now - p.ts < 30 * 60000 && !fresh.some((f) => f.i === p.i));
      run.pend[dev] = old.concat(fresh.map((f) => ({ i: f.i, t: f.t, b: f.b, ts: now })));
      changed = true;
    } else if (st === 404 || st === 410) { delete d.sub; gone = true; }
  }
  for (const k in run.sent) if (!live[k]) { delete run.sent[k]; changed = true; }
  for (const dev in run.pend) { const keep = run.pend[dev].filter((p) => now - p.ts < 30 * 60000); if (keep.length !== run.pend[dev].length) { run.pend[dev] = keep; changed = true; } }
  if (changed) await putJ(env, 'run', run);
  if (gone) await putJ(env, 'devs', devs);
}

export default {
  async fetch(req, env) {
    if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: CORS });
    const u = new URL(req.url), p = u.pathname;
    try {
      if (p === '/' ) return new Response('Righe notifiche: attivo.', { headers: { 'content-type': 'text/plain; charset=utf-8' } });
      if (p === '/init' && req.method === 'POST') {
        if (await getJ(env, 'cfg', null)) return json({ error: 'gia-attivo' }, 403);
        const cfg = await newConfig(); await putJ(env, 'cfg', cfg); return json({ key: cfg.key, pub: cfg.pub });
      }
      if (p === '/pub') { const cfg = await getJ(env, 'cfg', null); return cfg ? json({ pub: cfg.pub }) : json({ error: 'non-avviato' }, 404); }
      if (p === '/due') {
        const cfg = await authed(env, u.searchParams.get('key')); if (!cfg) return json({ error: 'chiave' }, 401);
        const run = await getJ(env, 'run', { pend: {} }), now = Date.now();
        return json({ items: ((run.pend || {})[u.searchParams.get('dev')] || []).filter((x) => now - x.ts < 30 * 60000) });
      }
      if (req.method === 'POST' && (p === '/sync' || p === '/unsync' || p === '/test')) {
        const b = await req.json(); const cfg = await authed(env, b.key); if (!cfg) return json({ error: 'chiave' }, 401);
        if (!b.dev || String(b.dev).length > 64) return json({ error: 'dispositivo' }, 400);
        const devs = await getJ(env, 'devs', {});
        if (p === '/unsync') { delete devs[b.dev]; await putJ(env, 'devs', devs); return json({ ok: true }); }
        if (p === '/sync') {
          const items = (Array.isArray(b.items) ? b.items : []).slice(0, 300).map((x) => ({ i: String(x.i).slice(0, 40), at: +x.at, rep: +x.rep || 0, t: String(x.t || '').slice(0, 120), b: String(x.b || '').slice(0, 200) })).filter((x) => x.i && x.at > 0);
          const old = devs[b.dev] || {};
          devs[b.dev] = { sub: b.sub && b.sub.endpoint ? { endpoint: String(b.sub.endpoint) } : old.sub, items, ts: Date.now() };
          await putJ(env, 'devs', devs); return json({ ok: true, n: items.length });
        }
        // prova immediata
        const d = devs[b.dev]; if (!d || !d.sub) return json({ error: 'senza-sub' }, 400);
        const run = await getJ(env, 'run', { sent: {}, pend: {} }); run.pend = run.pend || {};
        run.pend[b.dev] = (run.pend[b.dev] || []).concat([{ i: 'prova', t: 'Notifica di prova', b: 'Funziona: i promemoria arriveranno così.', ts: Date.now() }]);
        await putJ(env, 'run', run);
        const st = await sendPush(cfg, d.sub); return json({ ok: st >= 200 && st < 300, status: st });
      }
      return json({ error: 'non-trovato' }, 404);
    } catch (e) { return json({ error: String((e && e.message) || e) }, 500); }
  },
  async scheduled(ev, env, ctx) { ctx.waitUntil(tick(env)); }
};
export { tick, vapidHeader, newConfig };
