// ============================================================
// DOBE SCAN v15.2 — DexScreener + GMGN (Apify) + Full Checker
// ============================================================

// ============================================================
// SHARED HELPERS
// ============================================================
function json(status, body) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Headers': 'Content-Type',
      'Content-Type': 'application/json',
      'Cache-Control': 'no-store'
    }
  });
}

async function getJson(url, opts = {}) {
  try {
    const r = await fetch(url, {
      ...opts,
      signal: AbortSignal.timeout(9000),
      headers: { accept: 'application/json', ...(opts.headers || {}) }
    });
    if (!r.ok) return null;
    return await r.json();
  } catch { return null; }
}

async function postJson(url, body, opts = {}) {
  try {
    const r = await fetch(url, {
      ...opts,
      method: 'POST',
      signal: AbortSignal.timeout(9000),
      headers: { 'content-type': 'application/json', accept: 'application/json', ...(opts.headers || {}) },
      body: JSON.stringify(body)
    });
    if (!r.ok) return null;
    return await r.json();
  } catch { return null; }
}

function num(v) { const n = Number(v); return Number.isFinite(n) ? n : null; }
function clamp(v, min, max) { return Math.max(min, Math.min(max, v)); }

// ============================================================
// BASE64URL / VAPID
// ============================================================
function b64urlToUint8(b64url) {
  const pad = '='.repeat((4 - b64url.length % 4) % 4);
  const b64 = (b64url + pad).replace(/-/g, '+').replace(/_/g, '/');
  const raw = atob(b64);
  const arr = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) arr[i] = raw.charCodeAt(i);
  return arr;
}
function uint8ToB64url(arr) {
  let str = '';
  for (let i = 0; i < arr.length; i++) str += String.fromCharCode(arr[i]);
  return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
async function makeVapidJwt(audience, subject, publicKeyB64, privateKeyB64) {
  const header = { typ: 'JWT', alg: 'ES256' };
  const now = Math.floor(Date.now() / 1000);
  const payload = { aud: audience, exp: now + 12 * 3600, sub: subject };
  const enc = new TextEncoder();
  const headerB64 = uint8ToB64url(enc.encode(JSON.stringify(header)));
  const payloadB64 = uint8ToB64url(enc.encode(JSON.stringify(payload)));
  const unsigned = `${headerB64}.${payloadB64}`;
  const privRaw = b64urlToUint8(privateKeyB64);
  const pubRaw = b64urlToUint8(publicKeyB64);
  const jwk = { kty: 'EC', crv: 'P-256', d: uint8ToB64url(privRaw), x: uint8ToB64url(pubRaw.slice(1, 33)), y: uint8ToB64url(pubRaw.slice(33, 65)), ext: true };
  const key = await crypto.subtle.importKey('jwk', jwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, enc.encode(unsigned));
  return `${unsigned}.${uint8ToB64url(new Uint8Array(sig))}`;
}
async function sendPush(subscription, payload, env) {
  if (!env?.VAPID_PUBLIC_KEY || !env?.VAPID_PRIVATE_KEY) return false;
  const endpoint = subscription.endpoint;
  const url = new URL(endpoint);
  const audience = `${url.protocol}//${url.host}`;
  let jwt;
  try { jwt = await makeVapidJwt(audience, 'mailto:lexxpro99@gmail.com', env.VAPID_PUBLIC_KEY, env.VAPID_PRIVATE_KEY); } catch { return false; }
  try {
    const res = await fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'TTL': '86400', 'Authorization': `vapid t=${jwt}, k=${env.VAPID_PUBLIC_KEY}` },
      body: JSON.stringify(payload)
    });
    return res.ok || res.status === 201;
  } catch { return false; }
}

// ============================================================
// KV HELPERS
// ============================================================
const SUBS_KEY = 'push_subscriptions_v1';
const SEEN_KEY = 'seen_tokens_v1';
const SMART_KEY = 'smart_wallets_v1';
const SMART_TTL = 3600;

async function getSubscriptions(env) {
  if (!env?.SMART_CACHE) return [];
  try { const d = await env.SMART_CACHE.get(SUBS_KEY, { type: 'json' }); return Array.isArray(d) ? d : []; } catch { return []; }
}
async function saveSubscriptions(env, subs) {
  if (!env?.SMART_CACHE) return;
  try { await env.SMART_CACHE.put(SUBS_KEY, JSON.stringify(subs)); } catch {}
}
async function getSeenTokens(env) {
  if (!env?.SMART_CACHE) return new Map();
  try {
    const d = await env.SMART_CACHE.get(SEEN_KEY, { type: 'json' });
    if (Array.isArray(d)) {
      const m = new Map();
      for (const item of d) {
        if (typeof item === 'string') m.set(item, { modes: ['degen'] });
        else if (item?.addr) m.set(item.addr, { modes: item.modes || [] });
      }
      return m;
    }
    return new Map();
  } catch { return new Map(); }
}
async function saveSeenTokens(env, seenMap) {
  if (!env?.SMART_CACHE) return;
  try {
    const arr = Array.from(seenMap.entries()).slice(-800).map(([addr, info]) => ({ addr, modes: info.modes || [] }));
    await env.SMART_CACHE.put(SEEN_KEY, JSON.stringify(arr));
  } catch {}
}

// ============================================================
// PUSH HANDLERS
// ============================================================
async function handleSubscribe(request, env) {
  if (request.method !== 'POST') return json(405, { error: 'Method not allowed' });
  let body; try { body = await request.json(); } catch { return json(400, { error: 'Invalid JSON' }); }
  const sub = body?.subscription;
  if (!sub?.endpoint) return json(400, { error: 'Missing subscription.endpoint' });
  const subs = await getSubscriptions(env);
  if (!subs.some(s => s.endpoint === sub.endpoint)) {
    subs.push({ endpoint: sub.endpoint, keys: sub.keys || null, addedAt: Date.now() });
    await saveSubscriptions(env, subs);
  }
  return json(200, { ok: true, count: subs.length });
}
async function handleUnsubscribe(request, env) {
  if (request.method !== 'POST') return json(405, { error: 'Method not allowed' });
  let body; try { body = await request.json(); } catch { return json(400, { error: 'Invalid JSON' }); }
  const endpoint = body?.endpoint;
  if (!endpoint) return json(400, { error: 'Missing endpoint' });
  const subs = await getSubscriptions(env);
  const filtered = subs.filter(s => s.endpoint !== endpoint);
  await saveSubscriptions(env, filtered);
  return json(200, { ok: true, count: filtered.length });
}
async function handlePushTest(request, env) {
  const subs = await getSubscriptions(env);
  if (!subs.length) return json(200, { ok: true, sent: 0, message: 'No subscriptions' });
  let sent = 0;
  const payload = { title: 'DOBE Scan', body: 'Test notification — push works!', icon: '/icon-192.png', tag: 'test-' + Date.now(), url: '/screener?mode=degen' };
  for (const sub of subs) { if (await sendPush(sub, payload, env)) sent++; }
  return json(200, { ok: true, sent, total: subs.length });
}

// ============================================================
// SMART WALLETS (Cope Capital)
// ============================================================
async function fetchCopeLeaderboard() {
  let apiKey = null;
  try {
    const reg = await postJson('https://api.cope.capital/v1/register', { agent_name: 'dobe-scan-v15' });
    apiKey = reg?.key || reg?.api_key || reg?.data?.key || null;
  } catch { apiKey = null; }
  const headers = apiKey ? { Authorization: `Bearer ${apiKey}` } : {};
  const lb = await getJson('https://api.cope.capital/v1/leaderboard?timeframe=7d&limit=100', { headers });
  const results = lb?.results || lb?.data || lb?.leaderboard || [];
  if (!Array.isArray(results) || !results.length) return null;
  const wallets = results
    .map(r => ({ address: r.solana_address || r.wallet || r.address || null }))
    .filter(w => w.address && /^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(w.address));
  if (!wallets.length) return null;
  return { updatedAt: Date.now(), source: 'cope.capital', wallets };
}
async function getSmartWallets(env) {
  if (!env?.SMART_CACHE) return null;
  try {
    const c = await env.SMART_CACHE.get(SMART_KEY, { type: 'json' });
    if (c?.updatedAt && (Date.now() - c.updatedAt) < SMART_TTL * 1000) return c;
  } catch {}
  const fresh = await fetchCopeLeaderboard();
  if (fresh && env?.SMART_CACHE) {
    try { await env.SMART_CACHE.put(SMART_KEY, JSON.stringify(fresh), { expirationTtl: SMART_TTL }); } catch {}
  }
  return fresh || null;
}

// ============================================================
// APIFY + GMGN enrichment
// ============================================================
async function fetchGMGNEnrichment(addresses, env) {
  if (!env?.APIFY_TOKEN || !addresses.length) return new Map();

  const actorId = 'logiover~gmgn-trending-memecoin-scanner';
  const url = `https://api.apify.com/v2/acts/${actorId}/run-sync-get-dataset-items?token=${env.APIFY_TOKEN}&timeout=60`;

  const input = {
    mode: 'rugcheck',
    tokens: addresses.slice(0, 20).map(a => ({ chain: 'sol', address: a })),
    includeSecurity: true,
    includeDevInfo: true,
    includeTokenStat: true,
    includeBundlerStat: true,
    includeRugVote: true
  };

  try {
    const r = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(input),
      signal: AbortSignal.timeout(60000)
    });
    if (!r.ok) return new Map();
    const items = await r.json();
    if (!Array.isArray(items)) return new Map();

    const map = new Map();
    for (const item of items) {
      const addr = item.address || item.tokenAddress || item.token;
      if (!addr) continue;
      map.set(addr, {
        smart_degen_count: num(item.smart_degen_count) ?? 0,
        bundler_rate: num(item.bundler_rate) ?? 0,
        rug_ratio: num(item.rug_ratio) ?? 0,
        sniper_count: num(item.sniper_count) ?? 0,
        top10_holder_rate: num(item.top_10_holder_rate) ?? null,
        bluechip_owner_percentage: num(item.bluechip_owner_percentage) ?? null,
        is_honeypot: item.is_honeypot === 1 || item.is_honeypot === true,
        renounced_mint: item.renounced_mint === 1 || item.renounced_mint === true,
        renounced_freeze: item.renounced_freeze_account === 1 || item.renounced_freeze_account === true
      });
    }
    return map;
  } catch {
    return new Map();
  }
}

// ============================================================
// SCREENER — MODES
// ============================================================
const MODES = {
  showcase: { id: 'showcase', mc: [5000, 500000],  liq: 500,   age: [0.1, 168],  volLiqMin: 0.1, vol1hMin: 100,  vol1hRatio: 0.01, vol5mMin: 50,   tx5mMin: 1,  bsRatio: 0.8,  chgRange: [-60, 200] },
  degen:    { id: 'degen',    mc: [10000, 300000],  liq: 2000,  age: [0.5, 72],   volLiqMin: 0.5, vol1hMin: 300,  vol1hRatio: 0.05, vol5mMin: 200,  tx5mMin: 3,  bsRatio: 1.0,  chgRange: [-30, 100] },
  sniper:   { id: 'sniper',   mc: [20000, 200000],  liq: 5000,  age: [1, 48],     volLiqMin: 1.5, vol1hMin: 1000, vol1hRatio: 0.15, vol5mMin: 500,  tx5mMin: 10, bsRatio: 1.3,  chgRange: [-15, 50]  }
};

function sAgeHours(pairCreatedAt) { return pairCreatedAt ? (Date.now() - Number(pairCreatedAt)) / 36e5 : null; }

function passesFilters(t, mode) {
  const m = MODES[mode] || MODES.degen;
  const mc = num(t.marketCap);
  const liq = num(t.liquidity);
  const age = num(t.ageHours);
  const vol24 = num(t.volume24h);
  const vol1h = num(t.volume1h);
  const vol5m = num(t.volume5m);
  const buys5m = num(t.buys5m) || 0;
  const sells5m = num(t.sells5m) || 0;
  const tx5m = buys5m + sells5m;
  const buys1h = num(t.buys1h) || 0;
  const sells1h = num(t.sells1h) || 0;
  const chg24 = num(t.priceChange24h);

  if (mc == null || mc < m.mc[0] || mc > m.mc[1]) return false;
  if (liq == null || liq < m.liq) return false;
  if (age == null || age < m.age[0] || age > m.age[1]) return false;
  if (vol24 == null || vol24 < 100) return false;
  if (liq > 0 && vol24 / liq < m.volLiqMin) return false;
  if (vol1h == null || vol1h < m.vol1hMin) return false;
  if (vol24 > 0 && vol1h / vol24 < m.vol1hRatio) return false;
  if (chg24 != null && (chg24 < m.chgRange[0] || chg24 > m.chgRange[1])) return false;
  if (vol5m == null || vol5m < m.vol5mMin) return false;
  if (tx5m < m.tx5mMin) return false;
  if (buys1h < sells1h * m.bsRatio) return false;
  return true;
}

// ============================================================
// DEGEN SCORE
// ============================================================
function scoreSafety(t) {
  const liq = num(t.liquidity) || 0, mc = num(t.marketCap) || 0, vol24 = num(t.volume24h) || 0, age = num(t.ageHours);
  let s = 40;
  if (mc >= 50000 && mc <= 100000) s += 0; else if (mc < 50000) s -= 5; else s -= 3;
  if (liq < 20000) s -= 5; else if (liq > 60000) s += 3;
  if (age != null) { if (age >= 12 && age <= 36) s += 0; else if (age < 12) s -= 3; else s -= 2; }
  if (liq > 0) { const r = vol24 / liq; if (r >= 3 && r <= 10) s += 0; else if (r > 10) s -= 4; }
  return clamp(Math.round(s), 0, 40);
}
function scoreMomentum(t) {
  const vol1h = num(t.volume1h) || 0, vol24 = num(t.volume24h) || 0, vol5m = num(t.volume5m) || 0;
  const tx5m = (num(t.buys5m) || 0) + (num(t.sells5m) || 0);
  const buys1h = num(t.buys1h) || 0, sells1h = num(t.sells1h) || 0, chg24 = num(t.priceChange24h);
  let s = 0;
  if (vol24 > 0) { const r = vol1h / vol24; if (r >= 0.5) s += 15; else if (r >= 0.3) s += 10; else if (r >= 0.15) s += 5; }
  if (vol5m >= 15000) s += 10; else if (vol5m >= 8000) s += 7; else if (vol5m >= 5000) s += 4;
  if (tx5m >= 60) s += 5; else if (tx5m >= 30) s += 3; else if (tx5m >= 20) s += 1;
  if (sells1h > 0) { const r = buys1h / sells1h; if (r >= 2.5) s += 10; else if (r >= 2) s += 7; else if (r >= 1.5) s += 4; } else if (buys1h > 0) s += 10;
  if (chg24 != null) { if (chg24 >= -5 && chg24 <= 20) s += 5; else if (chg24 > 20 && chg24 <= 30) s += 2; else if (chg24 < -15) s -= 5; }
  return clamp(Math.round(s), 0, 40);
}
function scoreSmart(t, smartSet) {
  if (!smartSet || !smartSet.size) return { score: 0, flag: false };
  const age = num(t.ageHours);
  const buys1h = num(t.buys1h) || 0, sells1h = num(t.sells1h) || 0;
  let s = 0, flag = false;
  if (age != null && age <= 24) s += 5;
  if (buys1h >= 50) s += 5;
  if (sells1h > 0 && buys1h / sells1h >= 1.5) s += 5;
  if (smartSet.size >= 50) { s += 5; flag = smartSet.size >= 80; }
  return { score: clamp(s, 0, 20), flag };
}

function computeDegenScoreWithGMGN(t, smartSet, gmgn) {
  const safety = scoreSafety(t);
  const momentum = scoreMomentum(t);
  let smart = scoreSmart(t, smartSet).score;
  let smartFlag = false;

  if (gmgn) {
    smart = 0;
    if (gmgn.smart_degen_count >= 1) smart += 5;
    if (gmgn.smart_degen_count >= 3) smart += 5;
    if (gmgn.smart_degen_count >= 5) smart += 5;
    if (gmgn.smart_degen_count >= 10) smart += 5;
    smart = clamp(smart, 0, 20);
    smartFlag = gmgn.smart_degen_count >= 3;
  }

  const total = clamp(safety + momentum + smart, 0, 100);
  let tier = 'low';
  if (total >= 70) tier = 'high';
  else if (total >= 40) tier = 'mid';

  return { total, tier, safety, momentum, smart, smartFlag };
}

// ============================================================
// TOKEN MAPPER
// ============================================================
function mapPair(p) {
  const base = p.baseToken || {};
  const age = sAgeHours(p.pairCreatedAt);
  const buys1h = num(p.txns?.h1?.buys) || 0;
  const sells1h = num(p.txns?.h1?.sells) || 0;
  const buys5m = num(p.txns?.m5?.buys) || 0;
  const sells5m = num(p.txns?.m5?.sells) || 0;
  return {
    address: base.address,
    name: base.name || '—',
    symbol: base.symbol || '—',
    priceUsd: num(p.priceUsd),
    priceChange1h: num(p.priceChange?.h1),
    priceChange24h: num(p.priceChange?.h24),
    liquidity: num(p.liquidity?.usd),
    volume24h: num(p.volume?.h24),
    volume1h: num(p.volume?.h1),
    volume5m: num(p.volume?.m5),
    marketCap: num(p.marketCap) ?? num(p.fdv),
    buys1h, sells1h, buys5m, sells5m,
    ageHours: age,
    dex: p.dexId || null,
    pairUrl: p.url || null,
    logo: p.info?.imageUrl || null,
    links: {
      gmgn: `https://gmgn.ai/sol/token/${base.address}`,
      pump: `https://pump.fun/${base.address}`,
      axiom: `https://axiom.trade/t/${base.address}`
    }
  };
}

// ============================================================
// DISCOVERY
// ============================================================
async function fetchDexScreenerAll() {
  const urls = [
    'https://api.dexscreener.com/token-boosts/top/v1',
    'https://api.dexscreener.com/token-profiles/latest/v1',
    'https://api.dexscreener.com/latest/dex/search?q=solana'
  ];
  const results = await Promise.all(urls.map(u => getJson(u)));
  const pairs = [];
  const seen = new Set();
  const search = results[2];
  if (search?.pairs && Array.isArray(search.pairs)) {
    for (const p of search.pairs) {
      if (p.chainId === 'solana' && p.baseToken?.address && !seen.has(p.baseToken.address)) {
        seen.add(p.baseToken.address); pairs.push(p);
      }
    }
  }
  const extra = [];
  for (const r of [results[0], results[1]]) {
    if (!Array.isArray(r)) continue;
    for (const item of r) {
      const addr = item.tokenAddress || item.address;
      const chain = (item.chainId || '').toLowerCase();
      if (addr && (chain === 'solana' || !chain) && !seen.has(addr)) { extra.push(addr); seen.add(addr); }
    }
  }
  const batch = extra.slice(0, 30);
  if (batch.length) {
    const td = await getJson(`https://api.dexscreener.com/tokens/v1/solana/${batch.join(',')}`);
    const list = Array.isArray(td) ? td : td?.pairs || [];
    for (const p of list) { if (p?.chainId === 'solana' && p.baseToken?.address) pairs.push(p); }
  }
  return pairs;
}

// ============================================================
// SCREENER — CORE
// ============================================================
async function buildScreenerData(env, mode) {
  const pairs = await fetchDexScreenerAll();
  const seen = new Set();
  const merged = [];
  for (const p of pairs) {
    const addr = p.baseToken?.address;
    if (!addr || seen.has(addr)) continue;
    seen.add(addr);
    merged.push(mapPair(p));
  }

  // Stage 1: fast filter
  const filtered = merged.filter(t => passesFilters(t, mode));

  // Stage 2: enrich top-20 with GMGN via Apify
  const top = filtered.slice(0, 20);
  const addresses = top.map(t => t.address);
  const gmgnMap = await fetchGMGNEnrichment(addresses, env);

  const smart = await getSmartWallets(env);
  const smartSet = smart?.wallets?.length ? new Set(smart.wallets.map(w => w.address)) : null;

  const enriched = top.map(t => {
    const gmgn = gmgnMap.get(t.address) || null;
    const degen = computeDegenScoreWithGMGN(t, smartSet, gmgn);
    return { ...t, gmgn, degen };
  });

  enriched.sort((a, b) => {
    if (b.degen.total !== a.degen.total) return b.degen.total - a.degen.total;
    return (b.volume1h || 0) - (a.volume1h || 0);
  });

  return { filtered: enriched, smart };
}

async function handleScreener(request, env) {
  try {
    const url = new URL(request.url);
    const mode = (url.searchParams.get('mode') || 'showcase').toLowerCase();
    const validMode = MODES[mode] ? mode : 'showcase';

    const { filtered, smart } = await buildScreenerData(env, validMode);

    const seenMap = await getSeenTokens(env);
    for (const t of filtered) {
      const existing = seenMap.get(t.address);
      if (existing) { if (!existing.modes.includes(validMode)) existing.modes.push(validMode); }
      else seenMap.set(t.address, { modes: [validMode] });
    }
    await saveSeenTokens(env, seenMap);

    return json(200, {
      updatedAt: new Date().toISOString(),
      mode: validMode,
      count: filtered.length,
      smartWallets: smart?.wallets?.length || 0,
      tokens: filtered
    });
  } catch (e) {
    return json(500, { error: 'Screener error', detail: String(e?.message || e) });
  }
}

// ============================================================
// CHECKER — Full logic
// ============================================================
const NETWORKS = {
  solana: { name: 'Solana', rpc: 'https://api.mainnet-beta.solana.com', explorer: a => `https://solscan.io/token/${a}`, gmgn: a => `https://gmgn.ai/sol/token/${a}` }
};

function isSolana(a) { return /^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(a); }

async function fetchRugCheck(address, env) {
  const headers = {};
  if (env?.RUGCHECK_API_KEY) headers.Authorization = `Bearer ${env.RUGCHECK_API_KEY}`;
  const d = await getJson(`https://api.rugcheck.xyz/v1/tokens/${encodeURIComponent(address)}/report`, { headers });
  if (!d) return null;
  return {
    score: num(d.score_normalised),
    mintAuthority: d.token?.mintAuthority || null,
    freezeAuthority: d.token?.freezeAuthority || null,
    top10Pct: d.topHolders?.length ? d.topHolders.slice(0, 10).reduce((s, h) => s + Number(h.pct || 0), 0) : null,
    risks: Array.isArray(d.risks) ? d.risks.slice(0, 8) : []
  };
}

async function fetchGoPlusSolana(address, env) {
  const headers = {};
  if (env?.GOPLUS_API_KEY) headers.Authorization = `Bearer ${env.GOPLUS_API_KEY}`;
  const d = await getJson(`https://api.gopluslabs.io/api/v1/solana/token_security?contract_addresses=${encodeURIComponent(address)}`, { headers });
  const g = d?.result?.[address] || d?.result?.[Object.keys(d?.result || {})[0]] || null;
  if (!g) return null;
  return {
    mintable: g.mintable === '1' || g.mintable === 1 || g.mintable === true,
    freezable: g.freezable === '1' || g.freezable === 1 || g.freezable === true,
    malicious: g.malicious_address === '1' || g.fake_token === '1',
    trustedToken: g.trusted_token === '1',
    tokenName: g.token_name,
    tokenSymbol: g.token_symbol
  };
}

async function fetchJupiterSell(address) {
  const amount = '1000000';
  const urls = [
    `https://lite-api.jup.ag/swap/v1/quote?inputMint=${encodeURIComponent(address)}&outputMint=So11111111111111111111111111111111111111112&amount=${amount}&slippageBps=1500`,
    `https://quote-api.jup.ag/v6/quote?inputMint=${encodeURIComponent(address)}&outputMint=So11111111111111111111111111111111111111112&amount=${amount}&slippageBps=1500`
  ];
  for (const u of urls) {
    const q = await getJson(u);
    if (q) return { available: true, outAmount: q.outAmount, priceImpactPct: num(q.priceImpactPct), routeCount: Array.isArray(q.routePlan) ? q.routePlan.length : 1 };
  }
  return { available: false };
}

async function solanaRpc(rpc, method, params = []) {
  return postJson(rpc, { jsonrpc: '2.0', id: 1, method, params });
}
async function fetchOnchain(address, rpc) {
  const [ai, supply, largest] = await Promise.all([
    solanaRpc(rpc, 'getAccountInfo', [address, { encoding: 'jsonParsed', commitment: 'confirmed' }]),
    solanaRpc(rpc, 'getTokenSupply', [address, { commitment: 'confirmed' }]),
    solanaRpc(rpc, 'getTokenLargestAccounts', [address, { commitment: 'confirmed' }])
  ]);
  const i = ai?.result?.value;
  const parsed = i?.data?.parsed?.info || null;
  const s = supply?.result?.value || null;
  const ls = largest?.result?.value || [];
  if (!i && !s && !ls.length) return null;
  let top10 = null;
  if (s?.uiAmount && ls.length) {
    top10 = ls.slice(0, 10).reduce((a, x) => a + Number(x.uiAmount || 0), 0) / Number(s.uiAmount) * 100;
  }
  return {
    exists: !!i,
    ownerProgram: i?.owner || null,
    mintAuthority: parsed?.mintAuthority || null,
    freezeAuthority: parsed?.freezeAuthority || null,
    decimals: parsed?.decimals ?? s?.decimals ?? null,
    supply: s?.amount || null,
    uiSupply: s?.uiAmount || null,
    top10Pct: Number.isFinite(top10) ? top10 : null
  };
}

async function fetchGoPlusAddress(address, env) {
  const headers = {};
  if (env?.GOPLUS_API_KEY) headers.Authorization = `Bearer ${env.GOPLUS_API_KEY}`;
  const d = await getJson(`https://api.gopluslabs.io/api/v1/address_security/${encodeURIComponent(address)}`, { headers });
  return d?.result || null;
}

async function fetchPumpCoin(mint) {
  for (const u of [
    `https://frontend-api-v3.pump.fun/coins-v2/${encodeURIComponent(mint)}`,
    `https://frontend-api-v3.pump.fun/coins/${encodeURIComponent(mint)}?sync=true`
  ]) {
    const d = await getJson(u);
    if (d) return d;
  }
  return null;
}

async function creatorMigrationHistory(creator) {
  if (!creator) return null;
  const d = await getJson(`https://frontend-api-v3.pump.fun/coins/user-created-coins/${encodeURIComponent(creator)}?offset=0&limit=30&includeNsfw=false`);
  const tokens = Array.isArray(d) ? d.slice(0, 30) : (Array.isArray(d?.coins) ? d.coins.slice(0, 30) : []);
  if (!tokens.length) return { creator, total: 0, migrated: 0, pct: null, known: 0 };
  const migrated = tokens.filter(t => t.complete === true || t.raydium_pool || t.pump_swap_pool).length;
  return { creator, total: tokens.length, migrated, pct: tokens.length ? Math.round(migrated / tokens.length * 1000) / 10 : null, known: tokens.length };
}

async function checkSolana(address, env) {
  const rpc = NETWORKS.solana.rpc;
  const [rugcheck, goplus, jupiter, onchain, dex] = await Promise.all([
    fetchRugCheck(address, env).catch(() => null),
    fetchGoPlusSolana(address, env).catch(() => null),
    fetchJupiterSell(address).catch(() => null),
    fetchOnchain(address, rpc).catch(() => null),
    getJson(`https://api.dexscreener.com/latest/dex/tokens/${address}`).catch(() => null)
  ]);

  const market = dex?.pairs?.[0] ? {
    priceUsd: num(dex.pairs[0].priceUsd),
    priceChange24h: num(dex.pairs[0].priceChange?.h24),
    liquidity: num(dex.pairs[0].liquidity?.usd),
    volume24h: num(dex.pairs[0].volume?.h24),
    pairUrl: dex.pairs[0].url,
    dex: dex.pairs[0].dexId,
    logo: dex.pairs[0].info?.imageUrl || null,
    name: dex.pairs[0].baseToken?.name,
    symbol: dex.pairs[0].baseToken?.symbol
  } : null;

  const checks = [];
  const providers = [];
  const sources = [];
  const securitySources = [];
  let score = 0;
  let critical = false;

  if (rugcheck) {
    sources.push('RugCheck'); securitySources.push('RugCheck');
  }
  if (goplus) { sources.push('GoPlus Solana'); securitySources.push('GoPlus Solana'); }
  if (market) sources.push('DexScreener');

  const mintAuth = onchain?.mintAuthority || rugcheck?.mintAuthority;
  const freezeAuth = onchain?.freezeAuthority || rugcheck?.freezeAuthority;

  if (mintAuth) { checks.push({ id: 'mint', label: 'Mint Authority', status: 'red', value: 'Active', explain: 'Mint authority active — supply can be inflated.' }); score += 22; critical = true; }
  else checks.push({ id: 'mint', label: 'Mint Authority', status: 'green', value: 'Disabled', explain: 'Mint authority disabled.' });

  if (freezeAuth) { checks.push({ id: 'freeze', label: 'Freeze Authority', status: 'red', value: 'Active', explain: 'Freeze authority active — accounts can be frozen.' }); score += 18; critical = true; }
  else checks.push({ id: 'freeze', label: 'Freeze Authority', status: 'green', value: 'Disabled', explain: 'Freeze authority disabled.' });

  if (onchain) {
    securitySources.push('Public Solana RPC'); sources.push('Public Solana RPC');
    if (onchain.top10Pct != null) {
      const st = onchain.top10Pct > 50 ? 'red' : onchain.top10Pct > 30 ? 'yellow' : 'green';
      checks.push({ id: 'holders', label: 'Top 10 Holders', status: st, value: `${onchain.top10Pct.toFixed(1)}%`, explain: 'Concentration of top holders.' });
      if (onchain.top10Pct > 50) score += 22; else if (onchain.top10Pct > 30) score += 10;
    }
  }

  if (rugcheck?.score != null) {
    score = Math.max(score, Math.round(rugcheck.score * 0.85));
    providers.push({ name: 'RugCheck', status: rugcheck.score >= 55 ? 'red' : rugcheck.score >= 25 ? 'yellow' : 'green', score: rugcheck.score, detail: `score_normalised ${rugcheck.score}` });
  }

  if (rugcheck?.risks?.length) {
    rugcheck.risks.slice(0, 8).forEach(r => {
      const danger = r.level === 'danger' || r.level === 'critical';
      checks.push({ id: 'risk', label: r.name || 'RugCheck risk', status: danger ? 'red' : 'yellow', value: r.value || r.description || 'Flag', explain: r.description || '' });
      score += danger ? 9 : 4;
      if (danger) critical = true;
    });
  }

  if (goplus) {
    const bad = goplus.malicious;
    if (bad) { checks.push({ id: 'provider', label: 'GoPlus malicious-token flag', status: 'red', value: 'Detected', explain: 'Flagged by GoPlus.' }); score += 45; critical = true; }
    providers.push({ name: 'GoPlus Solana', status: bad ? 'red' : 'green', score: bad ? 95 : Math.min(55, score), detail: 'Token security' });
  }

  if (jupiter) {
    securitySources.push('Jupiter Sell Route'); sources.push('Jupiter Sell Route');
    if (jupiter.available) {
      const impact = jupiter.priceImpactPct;
      const st = impact != null && impact > 20 ? 'red' : impact != null && impact > 5 ? 'yellow' : 'green';
      checks.push({ id: 'sellroute', label: 'Sell Route', status: st, value: impact == null ? 'Route found' : `Route found · ${impact.toFixed(2)}% impact`, explain: 'Live DEX route check.' });
      if (impact > 20) { score += 30; critical = true; } else if (impact > 5) score += 10;
      providers.push({ name: 'Jupiter Sell Route', status: st, score: impact == null ? 5 : Math.min(100, impact * 3), detail: 'Public quote route' });
    } else if (market?.liquidity) {
      checks.push({ id: 'sellroute', label: 'Sell Route', status: 'red', value: 'NO ROUTE', explain: 'No sell route while DEX liquidity exists.' });
      score += 45; critical = true;
      providers.push({ name: 'Jupiter Sell Route', status: 'red', score: 95, detail: 'No route' });
    } else {
      checks.push({ id: 'sellroute', label: 'Sell Route', status: 'yellow', value: 'No route / no market', explain: 'No route — market unavailable.' });
      providers.push({ name: 'Jupiter Sell Route', status: 'yellow', score: 55, detail: 'No route' });
    }
  }

  // Dev reputation
  let dev = null;
  let migration = null;
  if (rugcheck && market) {
    // Try pump.fun creator
    const pump = await fetchPumpCoin(address).catch(() => null);
    const creator = pump?.creator || rugcheck?.creator || null;
    if (creator) {
      const [addrSec, hist] = await Promise.all([
        fetchGoPlusAddress(creator, env).catch(() => null),
        creatorMigrationHistory(creator).catch(() => null)
      ]);
      const reasons = [];
      if (addrSec) {
        if (addrSec.honeypot_related_address === '1' || addrSec.malicious_address === '1') reasons.push('scam/honeypot');
        if (addrSec.phishing_activities === '1') reasons.push('phishing');
        if (addrSec.stealing_attack === '1') reasons.push('stealing');
      }
      dev = { address: creator, checked: !!addrSec, malicious: reasons.length > 0, reasons, source: addrSec ? 'GoPlus' : null };
      if (reasons.length > 0) { checks.push({ id: 'dev', label: 'Dev Wallet Reputation', status: 'red', value: reasons.join(', '), explain: 'Dev flagged.' }); score += 60; critical = true; }
      migration = hist;
      if (hist?.pct != null) {
        const st = hist.pct >= 50 ? 'green' : hist.pct >= 20 ? 'yellow' : 'red';
        checks.push({ id: 'migration', label: 'Dev DEX Migration', status: st, value: `${hist.pct}% · ${hist.migrated}/${hist.known}`, explain: 'Historical DEX migration behavior.' });
        if (hist.pct < 20) score += 15; else if (hist.pct < 50) score += 7;
      }
    }
  }

  if (!checks.length) checks.push({ id: 'data', label: 'Security Data', status: 'gray', value: 'Unavailable', explain: 'No data.' });

  score = Math.min(100, Math.max(0, Math.round(score)));
  const confCount = securitySources.length;
  const conf = confCount >= 5 ? { score: 'high', label: { en: 'High', ru: 'Высокая', zh: '高' } }
    : confCount >= 3 ? { score: 'medium', label: { en: 'Medium', ru: 'Средняя', zh: '中' } }
    : { score: 'low', label: { en: 'Low', ru: 'Низкая', zh: '低' } };

  const lang = 'en';
  const lvl = critical ? 'red' : score == null ? 'yellow' : score < 25 ? 'green' : score < 55 ? 'yellow' : 'red';

  return {
    address,
    network: 'Solana',
    name: market?.name || goplus?.tokenName || '',
    symbol: market?.symbol || goplus?.tokenSymbol || '',
    logo: market?.logo || null,
    isNew: false,
    score: securitySources.length ? score : null,
    level: lvl,
    confidence: conf.score,
    confidenceLabel: conf.label[lang],
    checks,
    providers,
    serviceStatus: [
      ['RugCheck', !!rugcheck],
      ['GoPlus Solana', !!goplus],
      ['DexScreener', !!market],
      ['Jupiter Sell Route', !!jupiter],
      ['Public Solana RPC', !!onchain],
      ['Dev reputation', !!dev?.checked]
    ].map(([name, available]) => ({ name, available })),
    dev,
    creatorHistory: migration,
    market,
    sources,
    dataNotice: conf.score === 'low' ? 'Limited independent security data returned.' : null
  };
}

async function handleCheck(request, env) {
  const url = new URL(request.url);
  const p = Object.fromEntries(url.searchParams);
  const address = (p.address || '').trim();
  const network = (p.network || 'solana').toLowerCase();
  if (network !== 'solana') return json(400, { error: 'Only Solana supported' });
  if (!isSolana(address)) return json(400, { error: 'Invalid address' });
  try {
    const result = await checkSolana(address, env);
    result.explorerUrl = NETWORKS.solana.explorer(address);
    result.chartUrl = result.market?.pairUrl || NETWORKS.solana.gmgn(address);
    return json(200, result);
  } catch (e) {
    return json(200, {
      address, network: 'Solana', name: '', symbol: '', logo: null, isNew: false,
      score: null, level: 'yellow', confidence: 'low', confidenceLabel: 'Low',
      checks: [{ id: 'data', label: 'Security data', status: 'gray', value: 'Unavailable', explain: 'Fetch failed.' }],
      providers: [], serviceStatus: [], dev: null, market: null, sources: [],
      dataNotice: 'Incomplete data.'
    });
  }
}

// ============================================================
// CRON
// ============================================================
async function runCron(env) {
  const smart = await getSmartWallets(env);
  const smartSet = smart?.wallets?.length ? new Set(smart.wallets.map(w => w.address)) : null;
  const seenMap = await getSeenTokens(env);
  const subs = await getSubscriptions(env);
  const modeIds = ['showcase', 'degen', 'sniper'];
  const newByMode = { showcase: [], degen: [], sniper: [] };

  const { filtered: allTokens } = await buildScreenerData(env, 'showcase');

  for (const mode of modeIds) {
    const matches = allTokens.filter(t => passesFilters(t, mode)).map(t => ({ ...t }));
    for (const t of matches) {
      const existing = seenMap.get(t.address);
      if (!existing) { seenMap.set(t.address, { modes: [mode] }); newByMode[mode].push(t); }
      else if (!existing.modes.includes(mode)) { existing.modes.push(mode); newByMode[mode].push(t); }
    }
  }
  await saveSeenTokens(env, seenMap);
  if (!subs.length) return;

  const priorityOrder = ['sniper', 'degen', 'showcase'];
  for (const mode of priorityOrder) {
    const list = newByMode[mode];
    if (!list.length) continue;
    const top = list[0];
    const emoji = mode === 'sniper' ? '🔴' : mode === 'degen' ? '🟡' : '🟢';
    const label = mode === 'sniper' ? 'Sniper' : mode === 'degen' ? 'Degen' : 'Showcase';
    const payload = {
      title: `${emoji} ${label} · $${top.symbol} — ${top.degen?.total ?? '?'}`,
      body: `MC $${Math.round((top.marketCap || 0) / 1000)}K · Liq $${Math.round((top.liquidity || 0) / 1000)}K · Age ${top.ageHours?.toFixed(1) || '?'}h`,
      icon: top.logo || '/icon-192.png',
      tag: 'dobe-' + mode + '-' + top.address.slice(0, 8),
      url: '/screener?mode=' + mode
    };
    for (const sub of subs) { sendPush(sub, payload, env).catch(() => {}); }
  }
}

// ============================================================
// MAIN WORKER
// ============================================================
export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;
    if (request.method === 'OPTIONS') {
      return new Response(null, {
        status: 204,
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type'
        }
      });
    }
    try {
      if (path === '/api/check') return await handleCheck(request, env);
      if (path === '/api/screener') return await handleScreener(request, env);
      if (path === '/api/push/subscribe') return await handleSubscribe(request, env);
      if (path === '/api/push/unsubscribe') return await handleUnsubscribe(request, env);
      if (path === '/api/push/test') return await handlePushTest(request, env);
    } catch (e) {
      return json(500, { error: 'Internal error', detail: String(e?.message || e) });
    }
    if (env.ASSETS) return env.ASSETS.fetch(request);
    return new Response('Not found', { status: 404 });
  },
  async scheduled(event, env, ctx) { ctx.waitUntil(runCron(env)); }
};
