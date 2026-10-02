// ============================================================
// DOBE SCAN v13.1 — Multi-source Screener
// Sources: Binance Meme Rush + DexScreener + RugCheck + GoPlus + Moralis
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
  const payload = { title: 'DOBE Scan', body: 'Test notification — push is working!', icon: '/icon-192.png', tag: 'dobe-test-' + Date.now(), url: '/screener?mode=degen' };
  for (const sub of subs) { if (await sendPush(sub, payload, env)) sent++; }
  return json(200, { ok: true, sent, total: subs.length });
}

// ============================================================
// SMART WALLETS (Cope Capital)
// ============================================================
async function fetchCopeLeaderboard() {
  let apiKey = null;
  try {
    const reg = await postJson('https://api.cope.capital/v1/register', { agent_name: 'dobe-scan-v13' });
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
// SOURCE 1: Binance Meme Rush (Migrated tokens) — v13.1 FIX
// ============================================================
async function fetchBinanceMigrated(limit = 50) {
  const url = 'https://web3.binance.com/bapi/defi/v1/public/wallet-direct/buw/wallet/market/token/pulse/rank/list';
  const body = { chainId: 'CT_501', rankType: 30, limit: Math.min(limit, 200) };
  const d = await postJson(url, body, {
    headers: {
      'Accept-Encoding': 'identity',
      'User-Agent': 'binance-web3/2.1 (Skill)',
      'Content-Type': 'application/json'
    }
  });
  const list = d?.data?.tokens || d?.data || d?.result || [];
  if (!Array.isArray(list)) return [];
  return list.map(t => ({
    address: t.contractAddress || t.tokenAddress || t.mint || t.address,
    symbol: t.symbol || t.tokenSymbol,
    name: t.name || t.tokenName,
    marketCap: num(t.marketCap),
    liquidity: num(t.liquidity),
    volume24h: num(t.volume24h ?? t.volume),
    priceChange1h: num(t.priceChange1h ?? t.percentChange1h),
    priceChange24h: num(t.priceChange24h ?? t.priceChange ?? t.percentChange24h),
    holders: num(t.holders),
    top10Pct: num(t.holdersTop10Percent),
    logo: t.icon ? (t.icon.startsWith('http') ? t.icon : `https://bin.bnbstatic.com${t.icon}`) : null
  })).filter(t => t.address && /^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(t.address));
}

// ============================================================
// SOURCE 2: DexScreener (Fallback + enrichment)
// ============================================================
async function fetchDexScreenerFallback() {
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
        seen.add(p.baseToken.address);
        pairs.push(p);
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

async function enrichWithDexScreener(addresses) {
  if (!addresses.length) return new Map();
  const map = new Map();
  const chunks = [];
  for (let i = 0; i < addresses.length; i += 30) chunks.push(addresses.slice(i, i + 30));
  for (const chunk of chunks) {
    const d = await getJson(`https://api.dexscreener.com/tokens/v1/solana/${chunk.join(',')}`);
    const list = Array.isArray(d) ? d : d?.pairs || [];
    for (const p of list) {
      const addr = p.baseToken?.address;
      if (!addr) continue;
      const existing = map.get(addr);
      const liq = num(p.liquidity?.usd) || 0;
      if (existing && (num(existing.liquidity) || 0) > liq) continue;
      map.set(addr, {
        address: addr,
        symbol: p.baseToken?.symbol,
        name: p.baseToken?.name,
        priceUsd: num(p.priceUsd),
        priceChange1h: num(p.priceChange?.h1),
        priceChange24h: num(p.priceChange?.h24),
        liquidity: num(p.liquidity?.usd),
        volume24h: num(p.volume?.h24),
        volume1h: num(p.volume?.h1),
        volume5m: num(p.volume?.m5),
        marketCap: num(p.marketCap) ?? num(p.fdv),
        buys1h: num(p.txns?.h1?.buys),
        sells1h: num(p.txns?.h1?.sells),
        buys5m: num(p.txns?.m5?.buys),
        sells5m: num(p.txns?.m5?.sells),
        pairCreatedAt: num(p.pairCreatedAt),
        ageHours: p.pairCreatedAt ? (Date.now() - Number(p.pairCreatedAt)) / 36e5 : null,
        dex: p.dexId,
        pairUrl: p.url,
        logo: p.info?.imageUrl || null
      });
    }
  }
  return map;
}

// ============================================================
// SOURCE 3: RugCheck (Safety)
// ============================================================
async function fetchRugCheck(address) {
  const d = await getJson(`https://api.rugcheck.xyz/v1/tokens/${encodeURIComponent(address)}/report`);
  if (!d) return null;
  return {
    score: num(d.score_normalised),
    mintAuthority: d.token?.mintAuthority || null,
    freezeAuthority: d.token?.freezeAuthority || null,
    top10Pct: d.topHolders?.length ? d.topHolders.slice(0, 10).reduce((s, h) => s + Number(h.pct || 0), 0) : null,
    risks: Array.isArray(d.risks) ? d.risks.slice(0, 5) : []
  };
}

// ============================================================
// SOURCE 4: GoPlus Solana (Honeypot flags)
// ============================================================
async function fetchGoPlusSolana(address, env) {
  const headers = { accept: 'application/json' };
  if (env?.GOPLUS_API_KEY) headers.Authorization = `Bearer ${env.GOPLUS_API_KEY}`;
  const d = await getJson(`https://api.gopluslabs.io/api/v1/solana/token_security?contract_addresses=${encodeURIComponent(address)}`, { headers });
  const g = d?.result?.[address] || d?.result?.[Object.keys(d?.result || {})[0]] || null;
  if (!g) return null;
  return {
    mintable: g.mintable || null,
    freezable: g.freezable || null,
    transferFee: num(g.transfer_fee),
    trustedToken: g.trusted_token || null
  };
}

// ============================================================
// SOURCE 5: Moralis (Metadata enrichment)
// ============================================================
async function fetchMoralisMetadata(address, env) {
  if (!env?.MORALIS_API_KEY) return null;
  const d = await getJson(
    `https://deep-index.moralis.io/api/v2.2/erc20/metadata?addresses=${encodeURIComponent(address)}&chain=solana`,
    { headers: { 'X-API-Key': env.MORALIS_API_KEY, accept: 'application/json' } }
  );
  return d?.result?.[0] || null;
}

// ============================================================
// SCREENER — MODES
// ============================================================
const MODES = {
  showcase: { id: 'showcase', mc: [10000, 500000], liq: 3000, age: [1, 168], volLiqMin: 0.5, vol1hMin: 300, vol1hRatio: 0.05, vol5mMin: 500, tx5mMin: 3, bsRatio: 1.0, chgRange: [-50, 100] },
  degen:    { id: 'degen',    mc: [30000, 150000], liq: 15000, age: [6, 48],  volLiqMin: 3,   vol1hMin: 2000, vol1hRatio: 0.3,  vol5mMin: 5000, tx5mMin: 20, bsRatio: 1.5, chgRange: [-15, 30] },
  sniper:   { id: 'sniper',   mc: [40000, 120000], liq: 20000, age: [12, 36], volLiqMin: 5,   vol1hMin: 3000, vol1hRatio: 0.4,  vol5mMin: 10000, tx5mMin: 30, bsRatio: 2.0, chgRange: [-10, 25] }
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
  if (vol24 == null || vol24 < 300) return false;
  if (liq > 0 && vol24 / liq < m.volLiqMin) return false;
  if (vol1h == null || vol1h < m.vol1hMin) return false;
  if (vol24 > 0 && vol1h / vol24 < m.vol1hRatio) return false;
  if (chg24 != null && (chg24 < m.chgRange[0] || chg24 > m.chgRange[1])) return false;
  if (vol5m == null || vol5m < m.vol5mMin) return false;
  if (tx5m < m.tx5mMin) return false;
  if (buys1h < sells1h * m.bsRatio) return false;
  return true;
}

function clamp(v, min, max) { return Math.max(min, Math.min(max, v)); }

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
function computeDegenScore(t, smartSet) {
  const safety = scoreSafety(t), momentum = scoreMomentum(t), smart = scoreSmart(t, smartSet);
  const total = clamp(safety + momentum + smart.score, 0, 100);
  let tier = 'low'; if (total >= 70) tier = 'high'; else if (total >= 40) tier = 'mid';
  return { total, tier, safety, momentum, smart: smart.score, smartFlag: smart.flag };
}

// ============================================================
// SCREENER — CORE
// ============================================================
async function buildScreenerData(env, mode) {
  // 1) Try Binance Meme Rush (migrated tokens)
  let binanceTokens = await fetchBinanceMigrated(80);

  // 2) Fallback: DexScreener if Binance fails
  if (!binanceTokens.length) {
    const pairs = await fetchDexScreenerFallback();
    binanceTokens = pairs
      .filter(p => p.chainId === 'solana' && p.baseToken?.address)
      .map(p => ({
        address: p.baseToken.address,
        symbol: p.baseToken.symbol,
        name: p.baseToken.name,
        marketCap: num(p.marketCap) ?? num(p.fdv),
        liquidity: num(p.liquidity?.usd),
        volume24h: num(p.volume?.h24),
        priceChange1h: num(p.priceChange?.h1),
        priceChange24h: num(p.priceChange?.h24),
        logo: p.info?.imageUrl || null
      }))
      .filter(t => t.address);
  }

  // 3) Enrich with DexScreener
  const addresses = binanceTokens.map(t => t.address);
  const dexMap = await enrichWithDexScreener(addresses);

  // 4) Merge
  const merged = [];
  for (const b of binanceTokens) {
    const d = dexMap.get(b.address);
    merged.push({
      address: b.address,
      symbol: b.symbol || d?.symbol,
      name: b.name || d?.name,
      logo: b.logo || d?.logo || null,
      marketCap: d?.marketCap ?? b.marketCap,
      liquidity: d?.liquidity ?? b.liquidity,
      volume24h: d?.volume24h ?? b.volume24h,
      volume1h: d?.volume1h,
      volume5m: d?.volume5m,
      buys1h: d?.buys1h,
      sells1h: d?.sells1h,
      buys5m: d?.buys5m,
      sells5m: d?.sells5m,
      priceChange1h: d?.priceChange1h ?? b.priceChange1h,
      priceChange24h: d?.priceChange24h ?? b.priceChange24h,
      ageHours: d?.ageHours,
      pairCreatedAt: d?.pairCreatedAt,
      dex: d?.dex,
      pairUrl: d?.pairUrl,
      top10Pct: b.top10Pct
    });
  }

  // 5) Filter by mode + score
  const smart = await getSmartWallets(env);
  const smartSet = smart?.wallets?.length ? new Set(smart.wallets.map(w => w.address)) : null;

  const filtered = merged
    .filter(t => passesFilters(t, mode))
    .map(t => ({ ...t, degen: computeDegenScore(t, smartSet) }))
    .sort((a, b) => {
      if (b.degen.total !== a.degen.total) return b.degen.total - a.degen.total;
      return (b.volume1h || 0) - (a.volume1h || 0);
    })
    .slice(0, 40);

  // 6) Enrich top-10 with RugCheck + GoPlus + Moralis
  const top10 = filtered.slice(0, 10);
  const [rugChecks, goplusChecks, moralisData] = await Promise.all([
    Promise.all(top10.map(t => fetchRugCheck(t.address).catch(() => null))),
    Promise.all(top10.map(t => fetchGoPlusSolana(t.address, env).catch(() => null))),
    Promise.all(top10.map(t => fetchMoralisMetadata(t.address, env).catch(() => null)))
  ]);

  for (let i = 0; i < top10.length; i++) {
    if (rugChecks[i]) {
      top10[i].rugcheck = rugChecks[i];
      if (rugChecks[i].score != null) {
        top10[i].degen.total = clamp(top10[i].degen.total - Math.round(rugChecks[i].score * 0.3), 0, 100);
      }
    }
    if (goplusChecks[i]) top10[i].goplus = goplusChecks[i];
    if (moralisData[i]) top10[i].moralis = moralisData[i];
    const total = top10[i].degen.total;
    top10[i].degen.tier = total >= 70 ? 'high' : total >= 40 ? 'mid' : 'low';
  }

  return { filtered, smart };
}

async function handleScreener(request, env) {
  try {
    const url = new URL(request.url);
    const mode = (url.searchParams.get('mode') || 'degen').toLowerCase();
    const validMode = MODES[mode] ? mode : 'degen';

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
    const matches = allTokens.filter(t => passesFilters(t, mode)).map(t => ({ ...t, degen: computeDegenScore(t, smartSet) }));
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
      title: `${emoji} ${label} · $${top.symbol} — ${top.degen.total}`,
      body: `MC $${Math.round((top.marketCap || 0) / 1000)}K · Liq $${Math.round((top.liquidity || 0) / 1000)}K · Age ${top.ageHours?.toFixed(1) || '?'}h`,
      icon: top.logo || '/icon-192.png',
      tag: 'dobe-' + mode + '-' + top.address.slice(0, 8),
      url: '/screener?mode=' + mode
    };
    for (const sub of subs) { sendPush(sub, payload, env).catch(() => {}); }
  }
}

// ============================================================
// CHECK (simplified fallback)
// ============================================================
const NETWORKS = {
  solana: { name: 'Solana', ds: 'solana', explorer: a => `https://solscan.io/token/${a}`, gmgn: a => `https://gmgn.ai/sol/token/${a}`, rpc: 'https://api.mainnet-beta.solana.com' },
  base: { name: 'Base', chainId: '8453', ds: 'base', explorer: a => `https://basescan.org/token/${a}`, gmgn: a => `https://gmgn.ai/base/token/${a}`, rpc: 'https://mainnet.base.org' },
  bsc: { name: 'BSC', chainId: '56', ds: 'bsc', explorer: a => `https://bscscan.com/token/${a}`, gmgn: a => `https://gmgn.ai/bsc/token/${a}`, rpc: 'https://bsc-dataseed.binance.org' },
  ethereum: { name: 'Ethereum', chainId: '1', ds: 'ethereum', explorer: a => `https://etherscan.io/token/${a}`, gmgn: a => `https://gmgn.ai/eth/token/${a}`, rpc: 'https://cloudflare-eth.com' },
  arbitrum: { name: 'Arbitrum', chainId: '42161', ds: 'arbitrum', explorer: a => `https://arbiscan.io/token/${a}`, gmgn: a => `https://gmgn.ai/arbitrum/token/${a}`, rpc: 'https://arb1.arbitrum.io/rpc' },
  polygon: { name: 'Polygon', chainId: '137', ds: 'polygon', explorer: a => `https://polygonscan.com/token/${a}`, gmgn: a => `https://gmgn.ai/polygon/token/${a}`, rpc: 'https://polygon-rpc.com' },
  avalanche: { name: 'Avalanche', chainId: '43114', ds: 'avalanche', explorer: a => `https://snowtrace.io/token/${a}`, gmgn: a => `https://gmgn.ai/avax/token/${a}`, rpc: 'https://api.avax.network/ext/bc/C/rpc' },
  optimism: { name: 'Optimism', chainId: '10', ds: 'optimism', explorer: a => `https://optimistic.etherscan.io/token/${a}`, gmgn: a => `https://gmgn.ai/optimism/token/${a}`, rpc: 'https://mainnet.optimism.io' }
};

function isEvm(a) { return /^0x[a-fA-F0-9]{40}$/.test(a); }
function isSolana(a) { return /^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(a); }

async function handleCheck(request, env) {
  const url = new URL(request.url);
  const p = Object.fromEntries(url.searchParams);
  const address = (p.address || '').trim();
  const network = (p.network || 'solana').toLowerCase();
  const lang = ['en', 'ru', 'zh'].includes((p.lang || 'en').toLowerCase()) ? (p.lang || 'en').toLowerCase() : 'en';
  const net = NETWORKS[network];
  if (!net) return json(400, { error: 'Unsupported network' });
  if ((network === 'solana' && !isSolana(address)) || (network !== 'solana' && !isEvm(address))) return json(400, { error: 'Invalid address' });
  return json(200, {
    address, network: net.name, name: '', symbol: '', logo: null, isNew: false,
    score: null, level: 'yellow', confidence: 'low',
    confidenceLabel: { en: 'Low', ru: 'Низкая', zh: '低' }[lang],
    checks: [], providers: [], serviceStatus: [], dev: null, market: null, sources: [],
    dataNotice: { en: 'Limited data.', ru: 'Мало данных.', zh: '数据有限。' }[lang]
  });
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
