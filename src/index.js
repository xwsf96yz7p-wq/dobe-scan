// ============================================================
// DOBE SCAN v14 — OKX Trenches + DexScreener
// Sources: OKX MemePump (Migrated) + DexScreener (enrichment) + Moralis + RugCheck
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
    const reg = await postJson('https://api.cope.capital/v1/register', { agent_name: 'dobe-scan-v14' });
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
// SOURCE 1: OKX MemePump — MIGRATED tokens (FREE, no key)
// ============================================================
async function fetchOKXMigrated(limit = 60) {
  // chainIndex 501 = Solana, stage MIGRATED = completed migration to DEX
  const url = `https://web3.okx.com/api/v6/dex/market/memepump/tokenList?chainIndex=501&stage=MIGRATED&limit=${limit}`;
  const d = await getJson(url, {
    headers: {
      'Accept-Encoding': 'identity',
      'User-Agent': 'Mozilla/5.0 (compatible; DOBE-Scan/1.0)'
    }
  });
  const list = d?.data || [];
  if (!Array.isArray(list)) return [];
  return list.map(t => {
    // OKX returns nested market/tags objects
    const m = t.market || {};
    const tags = t.tags || {};
    return {
      address: t.tokenContractAddress,
      symbol: t.tokenSymbol,
      name: t.tokenName,
      logo: t.tokenLogo || null,
      marketCap: num(m.marketCapUsd),
      volume24h: num(m.volumeUsd),
      volume1h: num(m.volumeUsd1h),
      txCount1h: num(m.txCount1h),
      buys1h: num(m.buyTxCount1h),
      sells1h: num(m.sellTxCount1h),
      holders: num(tags.totalHolders),
      top10Pct: num(tags.top10HoldingsPercent),
      devHoldings: num(tags.devHoldingsPercent),
      insiders: num(tags.insidersPercent),
      bundlers: num(tags.bundlersPercent),
      snipers: num(tags.snipersPercent),
      freshWallets: num(tags.freshWalletsPercent),
      createdTimestamp: num(t.createdTimestamp)
    };
  }).filter(t => t.address && /^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(t.address));
}

// ============================================================
// SOURCE 2: DexScreener (enrichment)
// ============================================================
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
// SCREENER — MODES
// ============================================================
const MODES = {
  showcase: { id: 'showcase', mc: [5000, 500000],  liq: 500,   age: [0.1, 168],  volLiqMin: 0.1, vol1hMin: 100,  vol1hRatio: 0.01, vol5mMin: 50,   tx5mMin: 1,  bsRatio: 0.8,  chgRange: [-60, 200] },
  degen:    { id: 'degen',    mc: [10000, 300000],  liq: 2000,  age: [0.5, 72],   volLiqMin: 0.5, vol1hMin: 300,  vol1hRatio: 0.05, vol5mMin: 200,  tx5mMin: 3,  bsRatio: 1.0,  chgRange: [-30, 100] },
  sniper:   { id: 'sniper',   mc: [20000, 200000],  liq: 5000,  age: [1, 48],     volLiqMin: 1.5, vol1hMin: 1000, vol1hRatio: 0.15, vol5mMin: 500,  tx5mMin: 10, bsRatio: 1.3,  chgRange: [-15, 50]  }
};

function clamp(v, min, max) { return Math.max(min, Math.min(max, v)); }

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
  // 1) OKX MemePump — migrated tokens
  const okxTokens = await fetchOKXMigrated(60);

  // 2) Enrich with DexScreener
  const addresses = okxTokens.map(t => t.address);
  const dexMap = await enrichWithDexScreener(addresses);

  // 3) Merge
  const merged = [];
  for (const o of okxTokens) {
    const d = dexMap.get(o.address);
    merged.push({
      address: o.address,
      symbol: o.symbol || d?.symbol,
      name: o.name || d?.name,
      logo: o.logo || d?.logo || null,
      marketCap: d?.marketCap ?? o.marketCap,
      liquidity: d?.liquidity,
      volume24h: d?.volume24h ?? o.volume24h,
      volume1h: d?.volume1h ?? o.volume1h,
      volume5m: d?.volume5m,
      buys1h: d?.buys1h ?? o.buys1h,
      sells1h: d?.sells1h ?? o.sells1h,
      buys5m: d?.buys5m,
      sells5m: d?.sells5m,
      priceChange1h: d?.priceChange1h,
      priceChange24h: d?.priceChange24h,
      ageHours: d?.ageHours ?? (o.createdTimestamp ? (Date.now() - o.createdTimestamp) / 36e5 : null),
      pairCreatedAt: d?.pairCreatedAt,
      dex: d?.dex,
      pairUrl: d?.pairUrl,
      top10Pct: o.top10Pct,
      devHoldings: o.devHoldings
    });
  }

  // 4) Filter + score
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

  return { filtered, smart };
}

async function handleScreener(request, env) {
  try {
    const url = new URL(request.url);
    const mode = (url.searchParams.get('mode') || 'showcase').toLowerCase();
    const validMode = MODES[mode] ? mode : 'showcase';

    const { filtered, smart } = await buildScreenerData(env, validMode);

    // Update seen tokens
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
