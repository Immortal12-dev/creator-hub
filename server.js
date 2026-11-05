// GTAG Creator Hub — backend (Node 18+)
//   npm init -y && npm i express stripe nodemailer
//   Put this file next to GTAG_Creator_Hub_final.html, fill in .env (see .env.example), then:  node --env-file=.env server.js
//
// What it does
//   * Accounts: after paying, members create a username + password. Discord login and email-code login also work.
//   * On every /api/me it asks Stripe whether that email has an active subscription,
//     so buying unlocks access and cancelling removes it.
//   * The Discord invite is only ever sent to paid (Creator/Pro) members.

const express = require('express');
const crypto = require('crypto');
const path = require('path');
const Stripe = require('stripe');
const nodemailer = require('nodemailer');

const {
  STRIPE_KEY, SESSION_SECRET, BASE_URL = 'http://localhost:3000', DISCORD_INVITE,
  DISCORD_CLIENT_ID, DISCORD_CLIENT_SECRET,
  SMTP_HOST, SMTP_PORT = '587', SMTP_USER, SMTP_PASS, MAIL_FROM,
} = process.env;
for (const k of ['STRIPE_KEY', 'SESSION_SECRET', 'DISCORD_INVITE']) if (!process.env[k]) { console.error('Missing env var ' + k); process.exit(1); }

const stripe = new Stripe(STRIPE_KEY);
const mailer = SMTP_HOST ? nodemailer.createTransport({ host: SMTP_HOST, port: +SMTP_PORT, auth: { user: SMTP_USER, pass: SMTP_PASS } }) : null;
const SECURE = BASE_URL.startsWith('https');
const PAID = ['Creator', 'Pro'];
const app = express();
app.use(express.json());

/* ---------- signed-cookie sessions ---------- */
const sign = v => crypto.createHmac('sha256', SESSION_SECRET).update(v).digest('base64url');
function makeToken(data, ms) { const b = Buffer.from(JSON.stringify({ ...data, exp: Date.now() + ms })).toString('base64url'); return b + '.' + sign(b); }
function readToken(t) {
  if (!t) return null; const [b, sig] = t.split('.'); if (!b || !sig) return null;
  const good = sign(b); if (sig.length !== good.length || !crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(good))) return null;
  try { const d = JSON.parse(Buffer.from(b, 'base64url').toString()); return d.exp > Date.now() ? d : null; } catch { return null; }
}
const cookies = req => Object.fromEntries((req.headers.cookie || '').split(';').map(c => c.trim().split(/=(.*)/s).slice(0, 2)).filter(x => x[0]));
function setCookie(res, name, val, ms) {
  res.append('Set-Cookie', `${name}=${val}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${Math.floor(ms / 1000)}${SECURE ? '; Secure' : ''}`);
}
const clearCookie = (res, name) => res.append('Set-Cookie', `${name}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0`);
const DAY = 864e5 * 30;
const startSession = (res, u) => setCookie(res, 'sid', makeToken(u, DAY), DAY);

/* ---------- Stripe: what plan does this email have? ---------- */
const PRICE_TO_PLAN = {
  // price_xxx: 'Creator',   // optional exact mapping (Stripe > Product catalogue)
};
function planFromSub(sub) {
  const price = sub.items.data[0].price;
  if (PRICE_TO_PLAN[price.id]) return PRICE_TO_PLAN[price.id];
  const name = (price.product && price.product.name || '').toLowerCase();   // falls back to product name
  if (/\bpro\b/.test(name)) return 'Pro';
  if (/\bcreator\b/.test(name)) return 'Creator';
  if (/\bstarter\b/.test(name)) return 'Starter';
  return 'None';
}
const rank = { None: 0, Starter: 1, Creator: 2, Pro: 3 };
const cache = new Map();
async function planForEmail(email) {
  const hit = cache.get(email); if (hit && hit.t > Date.now() - 60000) return hit.plan;
  let best = 'None';
  const variants = [...new Set([email, email.toLowerCase()])];
  for (const e of variants) {
    const customers = await stripe.customers.list({ email: e, limit: 10 });
    for (const c of customers.data) {
      for (const status of ['active', 'trialing']) {
        const subs = await stripe.subscriptions.list({ customer: c.id, status, limit: 20, expand: ['data.items.data.price.product'] });
        for (const sub of subs.data) { const p = planFromSub(sub); if (rank[p] > rank[best]) best = p; }
      }
    }
  }
  cache.set(email, { plan: best, t: Date.now() });
  return best;
}

/* ---------- who am I ---------- */
app.get('/api/me', async (req, res) => {
  const u = readToken(cookies(req).sid);
  if (!u) return res.json({ loggedIn: false });
  try {
    const plan = await planForEmail(u.email);
    res.json({ loggedIn: true, email: u.email, username: u.username || '', provider: u.provider, plan, invite: PAID.includes(plan) ? DISCORD_INVITE : '' });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Could not check subscription' }); }
});
app.post('/auth/logout', (req, res) => { clearCookie(res, 'sid'); res.json({ ok: true }); });

/* ---------- email login with one-time code ---------- */
const codes = new Map(); // email -> {hash, exp, tries, last}
const hashCode = (email, code) => sign(email + ':' + code);
app.post('/auth/email/start', async (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  if (!/^[^@\s'"]+@[^@\s'"]+\.[^@\s'"]+$/.test(email)) return res.status(400).json({ error: 'Enter a valid email.' });
  const prev = codes.get(email);
  if (prev && Date.now() - prev.last < 60000) return res.status(429).json({ error: 'Please wait a minute before asking for another code.' });
  if (!mailer) return res.status(500).json({ error: 'Email sending is not set up yet.' });
  const code = String(crypto.randomInt(0, 1000000)).padStart(6, '0');
  codes.set(email, { hash: hashCode(email, code), exp: Date.now() + 600000, tries: 0, last: Date.now() });
  try {
    await mailer.sendMail({ from: MAIL_FROM || SMTP_USER, to: email, subject: 'Your GTAG Creator Hub login code', text: `Your login code is ${code}. It expires in 10 minutes. If you didn't ask for this, ignore this email.` });
    res.json({ ok: true });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Could not send the email.' }); }
});
app.post('/auth/email/verify', (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase(), code = String(req.body.code || '');
  const c = codes.get(email);
  if (!c || c.exp < Date.now()) return res.status(400).json({ error: 'That code has expired. Ask for a new one.' });
  if (++c.tries > 5) { codes.delete(email); return res.status(429).json({ error: 'Too many attempts. Ask for a new code.' }); }
  const ok = c.hash.length === hashCode(email, code).length && crypto.timingSafeEqual(Buffer.from(c.hash), Buffer.from(hashCode(email, code)));
  if (!ok) return res.status(400).json({ error: 'That code didn’t match.' });
  codes.delete(email);
  startSession(res, { email, provider: 'Email' });
  res.json({ ok: true });
});

/* ---------- Discord login (OAuth2) ---------- */
// Discord Developer Portal > your app > OAuth2 > add redirect:  BASE_URL + /auth/discord/callback
app.get('/auth/discord', (req, res) => {
  if (!DISCORD_CLIENT_ID) return res.status(500).send('Discord login is not set up yet.');
  const state = crypto.randomBytes(16).toString('hex');
  setCookie(res, 'dstate', state, 600000);
  res.redirect('https://discord.com/oauth2/authorize?' + new URLSearchParams({
    client_id: DISCORD_CLIENT_ID, redirect_uri: BASE_URL + '/auth/discord/callback', response_type: 'code', scope: 'identify email', state, prompt: 'none',
  }));
});
app.get('/auth/discord/callback', async (req, res) => {
  try {
    const { code, state } = req.query;
    if (!code || !state || state !== cookies(req).dstate) return res.redirect('/?login=error');
    clearCookie(res, 'dstate');
    const tok = await (await fetch('https://discord.com/api/oauth2/token', {
      method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ client_id: DISCORD_CLIENT_ID, client_secret: DISCORD_CLIENT_SECRET, grant_type: 'authorization_code', code, redirect_uri: BASE_URL + '/auth/discord/callback' }),
    })).json();
    if (!tok.access_token) return res.redirect('/?login=error');
    const me = await (await fetch('https://discord.com/api/users/@me', { headers: { Authorization: 'Bearer ' + tok.access_token } })).json();
    if (!me.email || !me.verified) return res.redirect('/?login=noemail');
    startSession(res, { email: me.email.toLowerCase(), username: me.global_name || me.username, provider: 'Discord', discordId: me.id });
    res.redirect('/?login=ok');
  } catch (e) { console.error(e); res.redirect('/?login=error'); }
});

/* ---------- accounts: username + password, stored on the Stripe customer (survives host restarts) ---------- */
const hashPw = (pw, salt) => crypto.scryptSync(pw, salt, 32).toString('hex');
const nameOk = u => /^[a-z0-9_]{3,20}$/.test(u);
async function userByName(u) { const r = await stripe.customers.search({ query: `metadata['gtag_user']:'${u}'`, limit: 1 }); return r.data[0] || null; }
async function userByEmail(email) {
  for (const e of new Set([email, email.toLowerCase()])) { const l = await stripe.customers.list({ email: e, limit: 20 }); const c = l.data.find(x => x.metadata && x.metadata.gtag_user); if (c) return c; }
  return null;
}
async function paidSession(id) {
  const cs = await stripe.checkout.sessions.retrieve(String(id || ''));
  return cs.status === 'complete' && ['paid', 'no_payment_required'].includes(cs.payment_status) && cs.customer && cs.customer_details && cs.customer_details.email ? cs : null;
}
app.get('/api/checkout-session', async (req, res) => {
  try {
    const cs = await paidSession(req.query.id); if (!cs) return res.status(400).json({ error: 'Payment not found' });
    const email = cs.customer_details.email.toLowerCase(); cache.delete(email);
    res.json({ ok: true, email, hasAccount: !!(await userByEmail(email)) });
  } catch (e) { res.status(400).json({ error: 'Payment not found' }); }
});
app.post('/auth/signup', async (req, res) => {
  try {
    const username = String(req.body.username || '').trim().toLowerCase(), pw = String(req.body.password || '');
    if (!nameOk(username)) return res.status(400).json({ error: 'Username must be 3–20 letters, numbers or _' });
    if (pw.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters.' });
    const cs = await paidSession(req.body.sessionId); if (!cs) return res.status(400).json({ error: 'We couldn’t find your payment.' });
    const email = cs.customer_details.email.toLowerCase();
    if (await userByEmail(email)) return res.status(409).json({ error: 'You already have an account. Please log in.' });
    if (await userByName(username)) return res.status(409).json({ error: 'That username is taken. Try another.' });
    const salt = crypto.randomBytes(16).toString('hex');
    await stripe.customers.update(cs.customer, { metadata: { gtag_user: username, gtag_pw: salt + ':' + hashPw(pw, salt) } });
    cache.delete(email); startSession(res, { email, username, provider: 'Password' }); res.json({ ok: true });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Could not create your account. Please try again.' }); }
});
const attempts = new Map();
app.post('/auth/login', async (req, res) => {
  const a = attempts.get(req.ip) || { n: 0, t: Date.now() };
  if (Date.now() - a.t > 9e5) { a.n = 0; a.t = Date.now(); }
  if (a.n >= 10) return res.status(429).json({ error: 'Too many attempts. Try again in 15 minutes.' });
  a.n++; attempts.set(req.ip, a);
  try {
    const u = String(req.body.username || '').trim().toLowerCase(), pw = String(req.body.password || '');
    const c = nameOk(u) && await userByName(u);
    const [salt, h] = ((c && c.metadata.gtag_pw) || 'x:x').split(':');
    const got = Buffer.from(hashPw(pw, salt)), want = Buffer.from(h);
    if (!c || got.length !== want.length || !crypto.timingSafeEqual(got, want)) return res.status(401).json({ error: 'Wrong username or password.' });
    startSession(res, { email: c.email.toLowerCase(), username: u, provider: 'Password' }); res.json({ ok: true });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Login failed. Please try again.' }); }
});

/* ---------- member perks (checked on the server, so they can't be unlocked from the browser) ---------- */
const TIER = { Starter: 1, Creator: 2, Pro: 3 };
const month = () => new Date().toLocaleString('en-GB', { month: 'long', year: 'numeric' });
const pick = (a, n) => a[n % a.length];
const T = {
  titles: t => ['I Tried ' + t + ' for 24 Hours', t + ': Nobody Tells You This', 'Stop Doing ' + t + ' Wrong', 'How I Got Better at ' + t + ' Fast', 'The ' + t + ' Challenge Went Too Far', 'Beginner vs Pro: ' + t, '5 ' + t + ' Tips You Need Right Now', 'Why Everyone Is Talking About ' + t].join('\n'),
  script: t => `HOOK (0–3s): Show the best moment of "${t}" first. No intro.\nSETUP (3–10s): State the challenge in one sentence.\nBUILD (10–40s): 3 attempts, each harder than the last.\nTWIST: One unexpected moment or fail.\nPAYOFF: Final result + your reaction.\nCTA: Ask "Want Part 2?" so people comment.`,
  hashtags: t => [...t.toLowerCase().replace(/[^a-z0-9 ]/g, '').split(/\s+/).filter(Boolean).slice(0, 3).map(x => '#' + x), '#gtag', '#gorillatag', '#vrgaming', '#gtagfunny', '#shorts', '#fyp'].join(' '),
  retention: m => { m = Math.min(20, Math.max(1, parseFloat(m) || 5)); const end = Math.round(m * 60), f = x => Math.floor(x / 60) + ':' + String(x % 60).padStart(2, '0'); let o = [`0:00  HOOK: best moment first`, `0:05  Quick setup, then straight into action`]; for (let x = 30, i = 0; x < end - 20; x += 30, i++) o.push(`${f(x)}  Pattern interrupt: ${pick(['zoom + sound hit', 'cut to new angle', 'on-screen text', 'speed ramp', 'reaction cutaway'], i)}`); o.push(`${f(Math.round(end / 2))}  Midpoint twist: raise the stakes`, `${f(end - 15)}  Payoff`, `${f(end)}  End on a question or Part 2 tease`); return o.join('\n'); },
};
const LIB = [
  { id: 'trends', tier: 'Starter', kind: 'text', title: 'Trend & growth updates', desc: 'Your update for ' + month(), body: () => `Trend & growth update: ${month()}\n\n• Movement showcases and custom game modes are the easiest clips to take off. Aim for 3 posts a week.\n• Series beat one-offs: "Day 1 vs Day 30" formats keep people subscribing.\n• Win the first 2 seconds: show the result or the wildest moment first.\n• Reply to comments in the first hour, then post Part 2 within 48 hours.` },
  { id: 'pfp', tier: 'Starter', kind: 'download', title: 'Monthly PFP pack', desc: month() + ' profile pictures (SVG)', file: () => ['gtag-pfp-pack.svg', 'image/svg+xml', pfpSheet()] },
  { id: 'bundle', tier: 'Starter', kind: 'download', title: 'Monthly digital bundle', desc: 'Title bank, hooks and a 4-week plan', file: () => ['gtag-bundle-' + month().replace(' ', '-') + '.txt', 'text/plain', `GTAG DIGITAL BUNDLE: ${month()}\n\nTITLE BANK\n` + T.titles('GTAG') + `\n\nHOOKS\n• Nobody believes this is possible in GTAG…\n• This one rule ruined the entire round.\n• Day 1 vs Day 30 of [skill].\n\n4-WEEK PLAN\nWeek 1: Movement showcase\nWeek 2: Custom game mode\nWeek 3: Tips & tricks short\nWeek 4: Best-of recap + community collab\n`] },
  { id: 'challenge', tier: 'Starter', kind: 'text', title: 'Challenge generator', desc: 'Included with your plan', body: () => 'Use the Challenge generator in the Creator tools section of the website (close the dashboard and scroll to Tools).' },
  { id: 'comp', tier: 'Creator', kind: 'text', title: 'Monthly competition', desc: month() + ' competition', body: () => `Monthly competition: ${month()}\n\nTheme: Best 30-second GTAG clip you made this month.\nHow to enter: post it in #competitions in the private Discord with your username.\nJudging: creativity, editing and fun.\nWinner announced at the end of the month. Prize announced in Discord.` },
  { id: 'titles', tier: 'Creator', kind: 'tool', title: 'Title booster', desc: 'Type your video topic, get 8 title ideas', ph: 'e.g. parkour challenge', run: T.titles },
  { id: 'script', tier: 'Creator', kind: 'tool', title: 'Script builder', desc: 'A short-form outline for any idea', ph: 'e.g. no-jump tag', run: T.script },
  { id: 'tags', tier: 'Creator', kind: 'tool', title: 'Hashtag pack', desc: 'Relevant hashtags for your topic', ph: 'e.g. funny moments', run: T.hashtags },
  { id: 'tpl-script', tier: 'Creator', kind: 'download', title: 'Script template', desc: 'Fill-in-the-blanks video script', file: () => ['script-template.txt', 'text/plain', 'TITLE:\nHOOK (0-3s):\nSETUP:\nBUILD (3 attempts):\nTWIST:\nPAYOFF:\nCTA:\nHASHTAGS:\n'] },
  { id: 'tpl-cal', tier: 'Creator', kind: 'download', title: '30-day content calendar', desc: 'Spreadsheet-ready CSV', file: () => ['content-calendar.csv', 'text/csv', 'Day,Format,Idea,Posted\n' + Array.from({ length: 30 }, (_, i) => `${i + 1},${pick(['Movement showcase', 'Challenge', 'Tips short', 'Funny moments', 'Series part', 'Collab'], i)},,No`).join('\n') + '\n'] },
  { id: 'tpl-thumb', tier: 'Creator', kind: 'download', title: 'Thumbnail template', desc: '1280×720 layout with safe zones (SVG)', file: () => ['thumbnail-template.svg', 'image/svg+xml', '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1280 720"><rect width="1280" height="720" fill="#0b1510"/><rect x="60" y="60" width="1160" height="600" fill="none" stroke="#00d084" stroke-dasharray="12 8"/><text x="90" y="130" fill="#00d084" font-size="34" font-family="sans-serif">SAFE ZONE: keep text &amp; faces inside</text><rect x="90" y="200" width="620" height="260" fill="#16352a"/><text x="110" y="340" fill="#fff" font-size="48" font-family="sans-serif">BIG TEXT (3 WORDS MAX)</text><circle cx="980" cy="360" r="190" fill="#16352a"/><text x="980" y="370" fill="#fff" font-size="32" text-anchor="middle" font-family="sans-serif">SUBJECT</text></svg>'] },
  { id: 'help', tier: 'Pro', kind: 'form', title: 'Priority creator help', desc: 'Ask a question and get a priority reply', ph: 'What do you need help with?' },
  { id: 'feedback', tier: 'Pro', kind: 'form', title: 'Custom content feedback', desc: 'Share a video and get personal feedback', ph: 'What would you like feedback on?' },
  { id: 'edit', tier: 'Pro', kind: 'text', title: 'Premium editing resources', desc: 'Pacing, captions, sound and export', body: () => 'PACING: a visual change every 2–3 seconds; cut dead air.\nCAPTIONS: large, high-contrast, 3–5 words at a time, kept inside the safe zone.\nSOUND: music under the voice; add a sound hit on every cut or twist.\nEXPORT: 1080×1920 for Shorts/TikTok, 1920×1080 for YouTube, 30 or 60 fps, H.264.\nWORKFLOW: rough cut → hook polish → captions → sound → export → thumbnail.' },
  { id: 'retention', tier: 'Pro', kind: 'tool', title: 'Early access: Retention planner', desc: 'New tool. Enter video length in minutes', ph: 'e.g. 5', run: T.retention },
];
const COLORS = [['#00d084', '#064'], ['#ff4d6d', '#400'], ['#4cc9f0', '#024'], ['#ffc857', '#430'], ['#b388ff', '#206'], ['#ff8fab', '#412']];
const pfpSheet = () => `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1020 720">` + COLORS.map((x, i) => { const cx = 170 + (i % 3) * 340, cy = 170 + Math.floor(i / 3) * 340; return `<defs><radialGradient id="g${i}"><stop offset="0" stop-color="${x[0]}"/><stop offset="1" stop-color="${x[1]}"/></radialGradient></defs><circle cx="${cx}" cy="${cy}" r="150" fill="url(#g${i})"/><text x="${cx}" y="${cy + 45}" font-size="130" text-anchor="middle">🦍</text>`; }).join('') + `<text x="510" y="705" font-size="24" fill="#888" text-anchor="middle" font-family="sans-serif">GTAG Creator Hub: ${month()} PFP pack</text></svg>`;
async function authed(req) { const u = readToken(cookies(req).sid); if (!u) return null; return { u, plan: await planForEmail(u.email) }; }
const allowed = (a, i) => a && rank[a.plan] >= TIER[i.tier];
app.get('/api/library', async (req, res) => {
  try {
    const a = await authed(req); if (!a || !rank[a.plan]) return res.status(403).json({ error: 'Members only' });
    res.json({ plan: a.plan, items: LIB.map(i => allowed(a, i)
      ? { id: i.id, tier: i.tier, kind: i.kind, title: i.title, desc: i.desc, ph: i.ph, body: i.body ? i.body() : undefined }
      : { id: i.id, tier: i.tier, kind: i.kind, title: i.title, desc: i.desc, locked: true }) });
  } catch (e) { res.status(500).json({ error: 'Could not load perks' }); }
});
app.get('/download/:id', async (req, res) => {
  try { const a = await authed(req), i = LIB.find(x => x.id === req.params.id && x.file); if (!i || !allowed(a, i)) return res.status(403).send('Members only');
    const [name, type, data] = i.file(); res.set({ 'Content-Type': type + '; charset=utf-8', 'Content-Disposition': `attachment; filename="${name}"` }).send(data);
  } catch (e) { res.status(500).send('Error'); }
});
app.post('/api/tool/:id', async (req, res) => {
  try { const a = await authed(req), i = LIB.find(x => x.id === req.params.id && x.run); if (!i || !allowed(a, i)) return res.status(403).json({ error: 'Not included in your plan.' });
    const input = String(req.body.input || '').trim().slice(0, 80); if (!input) return res.status(400).json({ error: 'Type something first.' });
    res.json({ output: i.run(input) });
  } catch (e) { res.status(500).json({ error: 'Tool failed.' }); }
});
app.post('/api/request', async (req, res) => {
  try { const a = await authed(req), i = LIB.find(x => x.id === req.params.id || x.id === req.body.id); if (!i || i.kind !== 'form' || !allowed(a, i)) return res.status(403).json({ error: 'Pro members only.' });
    const msg = String(req.body.message || '').trim().slice(0, 2000); if (!msg) return res.status(400).json({ error: 'Write a message first.' });
    if (!mailer) return res.status(500).json({ error: 'Email isn’t set up yet.' });
    await mailer.sendMail({ from: MAIL_FROM || SMTP_USER, to: process.env.MAIL_TO || SMTP_USER, replyTo: a.u.email, subject: `[PRO] ${i.title} from ${a.u.username || a.u.email}`, text: `${a.u.username || ''} <${a.u.email}> (${a.plan})\nLink: ${String(req.body.link || '').slice(0, 300)}\n\n${msg}` });
    res.json({ ok: true });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Could not send. Try again.' }); }
});

/* ---------- optional: live trends for the dashboard ---------- */
// Return { topics:[{t,h,why,idea}], tags:[], formats:[], updated:'' } — or {} to keep the built-in list.
app.get('/api/trends', async (req, res) => {
  const u = readToken(cookies(req).sid);
  if (!u || !rank[await planForEmail(u.email)]) return res.status(403).json({});
  res.json({});
});

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'GTAG_Creator_Hub_final.html')));
app.listen(3000, () => console.log('GTAG Hub running on ' + BASE_URL));
