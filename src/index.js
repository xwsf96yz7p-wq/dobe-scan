// ============================================================
// DOBE SCAN v19.1 — Sorted by firstSeenAt
// Checker: original 8 networks (untouched)
// Screener: 8 ratio filters + sort by first seen time
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
// KV HELPERS — с firstSeenAt
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
        if (typeof item === 'string') m.set(item, { modes: ['degen'], firstSeenAt: 0 });
        else if (item?.addr) m.set(item.addr, { modes: item.modes || [], firstSeenAt: item.firstSeenAt || 0 });
      }
      return m;
    }
    return new Map();
  } catch { return new Map(); }
}
async function saveSeenTokens(env, seenMap) {
  if (!env?.SMART_CACHE) return;
  try {
    const arr = Array.from(seenMap.entries()).slice(-1500).map(([addr, info]) => ({
      addr,
      modes: info.modes || [],
      firstSeenAt: info.firstSeenAt || 0
    }));
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
    const reg = await postJson('https://api.cope.capital/v1/register', { agent_name: 'dobe-scan-v19' });
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
// CHECKER — ORIGINAL (8 NETWORKS) — NOT TOUCHED
// ============================================================
const NETWORKS = {
  solana:    { name: 'Solana',    ds: 'solana',    explorer: a => `https://solscan.io/token/${a}`,               gmgn: a => `https://gmgn.ai/sol/token/${a}`,      rpc: 'https://api.mainnet-beta.solana.com' },
  base:      { name: 'Base',      chainId: '8453', ds: 'base',      explorer: a => `https://basescan.org/token/${a}`,             gmgn: a => `https://gmgn.ai/base/token/${a}`,     rpc: 'https://mainnet.base.org' },
  bsc:       { name: 'BSC',       chainId: '56',   ds: 'bsc',       explorer: a => `https://bscscan.com/token/${a}`,              gmgn: a => `https://gmgn.ai/bsc/token/${a}`,      rpc: 'https://bsc-dataseed.binance.org' },
  ethereum:  { name: 'Ethereum',  chainId: '1',    ds: 'ethereum',  explorer: a => `https://etherscan.io/token/${a}`,             gmgn: a => `https://gmgn.ai/eth/token/${a}`,      rpc: 'https://cloudflare-eth.com' },
  arbitrum:  { name: 'Arbitrum',  chainId: '42161',ds: 'arbitrum',  explorer: a => `https://arbiscan.io/token/${a}`,              gmgn: a => `https://gmgn.ai/arbitrum/token/${a}`, rpc: 'https://arb1.arbitrum.io/rpc' },
  polygon:   { name: 'Polygon',   chainId: '137',  ds: 'polygon',   explorer: a => `https://polygonscan.com/token/${a}`,          gmgn: a => `https://gmgn.ai/polygon/token/${a}`,  rpc: 'https://polygon-rpc.com' },
  avalanche: { name: 'Avalanche', chainId: '43114',ds: 'avalanche', explorer: a => `https://snowtrace.io/token/${a}`,             gmgn: a => `https://gmgn.ai/avax/token/${a}`,     rpc: 'https://api.avax.network/ext/bc/C/rpc' },
  optimism:  { name: 'Optimism',  chainId: '10',   ds: 'optimism',  explorer: a => `https://optimistic.etherscan.io/token/${a}`,  gmgn: a => `https://gmgn.ai/optimism/token/${a}`, rpc: 'https://mainnet.optimism.io' }
};

const EXPLAIN = {
  honeypot:{en:'A security provider detected a honeypot or sell restriction.',ru:'Security-сервис обнаружил honeypot или ограничение продажи.',zh:'安全服务检测到蜜罐或卖出限制。'},
  ownership:{en:'Owner/admin control remains.',ru:'У владельца/админа остаётся контроль.',zh:'所有者/管理员仍有控制权。'},
  mintable:{en:'Mint authority can increase supply.',ru:'Mint authority может увеличить supply.',zh:'铸币权限可以增加供应量。'},
  tax:{en:'Reported buy/sell tax.',ru:'Заявленный buy/sell tax.',zh:'报告的买卖税。'},
  proxy:{en:'Upgradeable/proxy logic can change later.',ru:'Upgradeable/proxy-логика может быть изменена.',zh:'可升级/代理逻辑可能改变。'},
  verified:{en:'Verified/open-source code improves transparency.',ru:'Верифицированный код повышает прозрачность.',zh:'已验证代码提高透明度。'},
  holders:{en:'Holder concentration can create sell-pressure risk.',ru:'Концентрация холдеров создаёт риск.',zh:'持仓集中可能带来风险。'},
  blacklist:{en:'Blacklist capability can restrict addresses.',ru:'Blacklist может ограничивать адреса.',zh:'黑名单功能可能限制地址。'},
  pause:{en:'Transfers may be paused by an administrator.',ru:'Администратор может остановить переводы.',zh:'管理员可能暂停转账。'},
  modTax:{en:'Tax appears changeable.',ru:'Налог можно менять.',zh:'税率可能修改。'},
  sellroute:{en:'A live DEX route checks whether the token can currently be sold.',ru:'Живой DEX-маршрут проверяет, можно ли продать токен.',zh:'实时 DEX 路由检查代币是否可卖。'},
  dev:{en:'Developer/deployer reputation.',ru:'Репутация dev/deployer.',zh:'开发者信誉。'},
  migration:{en:'Historical DEX migration behavior.',ru:'История выхода токенов этого dev на DEX.',zh:'开发者历史代币进入 DEX 的情况。'},
  onchain:{en:'Direct blockchain data via public RPC.',ru:'Прямые данные блокчейна через публичный RPC.',zh:'通过公共 RPC 获取链上数据。'},
  token2022:{en:'Solana Token-2022 extensions need review.',ru:'Расширения Solana Token-2022 требуют проверки。',zh:'Solana Token-2022 扩展需要检查。'},
  data:{en:'Insufficient data.',ru:'Недостаточно данных.',zh:'数据不足。'}
};

function isEvm(a){return /^0x[a-fA-F0-9]{40}$/.test(a)}
function isSolana(a){return /^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(a)}
function flag(v){return v==='1'||v===1||v===true||v==='true'}
function valKnown(v){return v!==undefined&&v!==null&&v!==''}
function pct(v){if(!valKnown(v))return null;const n=Number(v);if(!Number.isFinite(n))return null;return n<=1?n*100:n}
function confidence(count){return count>=5?{score:'high',label:{en:'High',ru:'Высокая',zh:'高'}}:count>=3?{score:'medium',label:{en:'Medium',ru:'Средняя',zh:'中'}}:{score:'low',label:{en:'Low',ru:'Низкая',zh:'低'}}}
function level(score){return score<25?'green':score<55?'yellow':'red'}
function finalLevel(score,critical){if(critical)return'red';if(score==null)return'yellow';return level(score)}
function localExplain(id,lang){return(EXPLAIN[id]&&EXPLAIN[id][lang])||EXPLAIN[id]?.en||EXPLAIN.data.en}
function addCheck(checks,id,label,status,value,lang,extra){checks.push({id,label,status,value,explain:extra||localExplain(id,lang)})}
function addProvider(providers,name,status,score,detail){providers.push({name,status,score:score==null?null:Math.round(Math.max(0,Math.min(100,score))),detail:detail||''})}
function first(...xs){return xs.find(valKnown)}
function authHeaders(provider,env){const h={accept:'application/json'};if(provider==='goplus'&&env?.GOPLUS_API_KEY)h.Authorization=`Bearer ${env.GOPLUS_API_KEY}`;if(provider==='rugcheck'&&env?.RUGCHECK_API_KEY)h.Authorization=`Bearer ${env.RUGCHECK_API_KEY}`;return h}

async function fetchDex(address,chain){
  const d=await getJson(`https://api.dexscreener.com/latest/dex/tokens/${encodeURIComponent(address)}`);
  if(!d?.pairs?.length)return null;
  let ps=d.pairs.filter(p=>!chain||p.chainId===chain);
  if(!ps.length)ps=d.pairs;
  ps.sort((a,b)=>(b.liquidity?.usd||0)-(a.liquidity?.usd||0));
  const p=ps[0],tx=p.txns?.h24||{},created=p.pairCreatedAt?Number(p.pairCreatedAt):null;
  return{
    priceUsd:p.priceUsd,priceChange24h:p.priceChange?.h24,liquidity:p.liquidity?.usd,volume24h:p.volume?.h24,fdv:p.fdv,pairUrl:p.url,dex:p.dexId,pairCreatedAt:created,
    ageHours:created?(Date.now()-created)/36e5:null,logo:p.info?.imageUrl||null,name:p.baseToken?.name,symbol:p.baseToken?.symbol,
    buys24h:tx.buys||0,sells24h:tx.sells||0,txns24h:(tx.buys||0)+(tx.sells||0),pairAddress:p.pairAddress||null
  };
}

async function fetchJupiterSell(address,supply,decimals){
  if(!supply||!Number.isFinite(Number(decimals)))return null;
  let raw;try{raw=BigInt(String(supply))}catch{return null}
  const d=Math.max(0,Math.min(18,Number(decimals)));
  let amount=raw/10000n;
  const min=10n**BigInt(Math.min(d,6));
  if(amount<min)amount=min;
  const urls=[
    `https://lite-api.jup.ag/swap/v1/quote?inputMint=${encodeURIComponent(address)}&outputMint=So11111111111111111111111111111111111111112&amount=${amount}&slippageBps=1500&restrictIntermediateTokens=true`,
    `https://quote-api.jup.ag/v6/quote?inputMint=${encodeURIComponent(address)}&outputMint=So11111111111111111111111111111111111111112&amount=${amount}&slippageBps=1500`
  ];
  for(const u of urls){
    const q=await getJson(u);
    if(q)return{available:true,amount:amount.toString(),outAmount:q.outAmount||null,priceImpactPct:valKnown(q.priceImpactPct)?Number(q.priceImpactPct):null,routeCount:Array.isArray(q.routePlan)?q.routePlan.length:null};
  }
  return{available:false,amount:amount.toString(),outAmount:null,priceImpactPct:null,routeCount:0};
}

async function fetchGoPlusAddress(address,chainId,env){
  const d=await getJson(`https://api.gopluslabs.io/api/v1/address_security/${encodeURIComponent(address)}${chainId?`?chain_id=${encodeURIComponent(chainId)}`:''}`,{headers:authHeaders('goplus',env)});
  return d?.result||null;
}
function normalizeMaliciousAddress(a){
  if(!a)return null;
  const reasons=[];
  if(flag(a.honeypot_related_address)||flag(a.malicious_address))reasons.push('scam/honeypot');
  if(flag(a.phishing_activities))reasons.push('phishing');
  if(flag(a.stealing_attack))reasons.push('stealing');
  if(flag(a.blackmail_activities))reasons.push('blackmail');
  if(flag(a.cybercrime))reasons.push('cybercrime');
  if(flag(a.sanctioned))reasons.push('sanctioned');
  const count=Number(a.number_of_malicious_contracts_created||0);
  if(count>0)reasons.push(`${count} malicious contracts`);
  return{checked:true,malicious:reasons.length>0,reasons,raw:a};
}

async function fetchPumpCoin(mint){
  for(const u of [`https://frontend-api-v3.pump.fun/coins-v2/${encodeURIComponent(mint)}`,`https://frontend-api-v3.pump.fun/coins/${encodeURIComponent(mint)}?sync=true`]){
    const d=await getJson(u);if(d)return d;
  }
  return null;
}
async function creatorMigrationHistory(creator,creatorTokens){
  if(!creator)return null;
  let tokens=Array.isArray(creatorTokens)?creatorTokens.slice(0,30):[];
  if(!tokens.length){
    const d=await getJson(`https://frontend-api-v3.pump.fun/coins/user-created-coins/${encodeURIComponent(creator)}?offset=0&limit=30&includeNsfw=false`);
    if(Array.isArray(d))tokens=d.slice(0,30);else if(Array.isArray(d?.coins))tokens=d.coins.slice(0,30);
  }
  if(!tokens.length)return{creator,total:0,migrated:0,pct:null,known:0,source:'Pump.fun + DexScreener'};
  const details=[];let idx=0;
  const workers=Array.from({length:5},async()=>{
    while(idx<tokens.length){
      const i=idx++,t=tokens[i]||{},mint=t.mint||t.address;
      const[d,dx]=await Promise.all([mint?fetchPumpCoin(mint):Promise.resolve(null),mint?fetchDex(mint,'solana'):Promise.resolve(null)]);
      const complete=d?.complete??t.complete??null;
      const pool=d?.raydium_pool||d?.pump_swap_pool||d?.raydiumPool||t.raydium_pool||null;
      const hasDexPair=!!dx?.pairAddress||!!dx?.pairUrl;
      details[i]={mint,complete,pool,hasDexPair};
    }
  });
  await Promise.all(workers);
  const known=details.filter(x=>x&&((x.complete!==null)||x.hasDexPair)).length;
  const migrated=details.filter(x=>x&&(x.complete===true||!!x.pool||x.hasDexPair)).length;
  return{creator,total:details.length,migrated,pct:known?Math.round(migrated/known*1000)/10:null,known,source:'Pump.fun + DexScreener'};
}

async function solanaRpc(rpc,method,params=[]){return postJson(rpc,{jsonrpc:'2.0',id:1,method,params})}
async function fetchSolanaOnchain(address,rpc){
  const [ai,supply,largest]=await Promise.all([
    solanaRpc(rpc,'getAccountInfo',[address,{encoding:'jsonParsed',commitment:'confirmed'}]),
    solanaRpc(rpc,'getTokenSupply',[address,{commitment:'confirmed'}]),
    solanaRpc(rpc,'getTokenLargestAccounts',[address,{commitment:'confirmed'}])
  ]);
  const info=ai?.result?.value,parsed=info?.data?.parsed?.info||null,s=supply?.result?.value||null,ls=largest?.result?.value||[];
  if(!info&&!s&&!ls.length)return null;
  let top10=null;
  if(s?.uiAmount&&ls.length)top10=ls.slice(0,10).reduce((a,x)=>a+Number(x.uiAmount||0),0)/Number(s.uiAmount)*100;
  return{exists:!!info,ownerProgram:info?.owner||null,mintAuthority:parsed?.mintAuthority||null,freezeAuthority:parsed?.freezeAuthority||null,decimals:parsed?.decimals??s?.decimals??null,supply:s?.amount||null,uiSupply:s?.uiAmount||null,top10Pct:Number.isFinite(top10)?top10:null,largest:ls.slice(0,10).map(x=>({address:x.address,amount:x.amount,uiAmount:x.uiAmount}))};
}

const EVM_SELECTORS={name:'0x06fdde03',symbol:'0x95d89b41',decimals:'0x313ce567',totalSupply:'0x18160ddd'};
function decodeUint(hex){try{return hex?Number(BigInt(hex)):null}catch{return null}}
function decodeString(hex){
  if(!hex||hex==='0x')return null;
  try{
    const h=hex.slice(2);
    if(h.length>=128){
      const offset=Number(BigInt('0x'+h.slice(0,64)));
      const start=offset*2;
      const len=Number(BigInt('0x'+h.slice(start,start+64)));
      const data=h.slice(start+64,start+64+len*2);
      return atob(data).replace(/\0/g,'');
    }
    return atob(h).replace(/\0/g,'');
  }catch{return null}
}
async function evmCall(rpc,to,data){const d=await postJson(rpc,{jsonrpc:'2.0',id:1,method:'eth_call',params:[{to,data},'latest']});return d?.result||null}
async function fetchEvmOnchain(address,rpc){
  const [code,name,symbol,decimals,supply]=await Promise.all([
    postJson(rpc,{jsonrpc:'2.0',id:1,method:'eth_getCode',params:[address,'latest']}),
    evmCall(rpc,address,EVM_SELECTORS.name),
    evmCall(rpc,address,EVM_SELECTORS.symbol),
    evmCall(rpc,address,EVM_SELECTORS.decimals),
    evmCall(rpc,address,EVM_SELECTORS.totalSupply)
  ]);
  const bytecode=code?.result;
  if(!bytecode)return null;
  return{contract:bytecode!=='0x',bytecodeBytes:bytecode&&bytecode!=='0x'?(bytecode.length-2)/2:0,name:decodeString(name),symbol:decodeString(symbol),decimals:decodeUint(decimals),totalSupply:supply?String(BigInt(supply)):null};
}

async function fetchHoneypot(address,chainId){if(!['1','56','8453'].includes(chainId))return null;return getJson(`https://api.honeypot.is/v2/IsHoneypot?address=${encodeURIComponent(address)}&chainID=${encodeURIComponent(chainId)}`)}
async function fetchTokenSniffer(address,chainId,env){if(!env?.TOKENSNIFFER_API_KEY)return null;return getJson(`https://tokensniffer.com/api/v2/tokens/${chainId}/${encodeURIComponent(address)}?include_metrics=true&include_tests=true&include_similar=true`,{headers:{'X-API-Key':env.TOKENSNIFFER_API_KEY}})}

async function checkEVM(address,net,lang,env){
  const [gp,hp,market,ts,onchain]=await Promise.all([
    getJson(`https://api.gopluslabs.io/api/v1/token_security/${net.chainId}?contract_addresses=${encodeURIComponent(address)}`,{headers:authHeaders('goplus',env)}),
    fetchHoneypot(address,net.chainId),
    fetchDex(address,net.ds),
    fetchTokenSniffer(address,net.chainId,env),
    fetchEvmOnchain(address,net.rpc)
  ]);
  const g=gp?.result?.[address.toLowerCase()]||gp?.result?.[Object.keys(gp?.result||{})[0]]||null;
  const devAddress=g?.creator_address||g?.owner_address||null;
  const addrSec=devAddress?await fetchGoPlusAddress(devAddress,net.chainId,env):null;
  const checks=[],providers=[],sources=[],securitySources=[];let score=0,critical=false;
  let name=market?.name||onchain?.name||'',symbol=market?.symbol||onchain?.symbol||'',logo=market?.logo||null;

  if(g){
    sources.push('GoPlus');securitySources.push('GoPlus');
    const honeypot=flag(g.is_honeypot);
    if(honeypot){addCheck(checks,'honeypot','Honeypot','red','Detected',lang);score+=55;critical=true}
    else addCheck(checks,'honeypot','Honeypot','green','Not detected',lang);
    const open=flag(g.is_open_source);
    addCheck(checks,'verified','Open Source','green',open?'Yes':'No',lang);
    if(!open)score+=5;
    const mint=flag(g.is_mintable);
    addCheck(checks,'mintable','Mintable','red',mint?'Yes':'No',lang);
    if(mint){score+=22;critical=true}
    const proxy=flag(g.is_proxy);
    addCheck(checks,'proxy','Proxy / Upgradeable',proxy?'yellow':'green',proxy?'Yes':'No',lang);
    if(proxy)score+=8;
    const owner=valKnown(g.owner_address)?g.owner_address:null;
    if(owner){
      const renounced=/^0x0{40}$/i.test(owner)||/^0x0{64}$/i.test(owner);
      addCheck(checks,'ownership','Owner Control',renounced?'green':'yellow',renounced?'Renounced':'Present',lang);
      if(!renounced)score+=6;
    }
    const buyTax=pct(g.buy_tax),sellTax=pct(g.sell_tax);
    if(buyTax!==null||sellTax!==null){
      const mx=Math.max(buyTax||0,sellTax||0),st=mx>15?'red':mx>5?'yellow':'green';
      addCheck(checks,'tax','Buy / Sell Tax',st,`${(buyTax??0).toFixed(1)}% / ${(sellTax??0).toFixed(1)}%`,lang);
      if(mx>15){score+=25;critical=true}else if(mx>5)score+=10;
    }
    if(valKnown(g.slippage_modifiable)){
      const x=flag(g.slippage_modifiable);
      addCheck(checks,'modTax','Tax Modifiable',x?'yellow':'green',x?'Yes':'No',lang);
      if(x)score+=10;
    }
    if(valKnown(g.transfer_pausable)){
      const x=flag(g.transfer_pausable);
      addCheck(checks,'pause','Trading Pausable',x?'red':'green',x?'Yes':'No',lang);
      if(x){score+=15;critical=true}
    }
    const bl=valKnown(g.is_blacklisted)?flag(g.is_blacklisted):null;
    if(bl!==null){addCheck(checks,'blacklist','Blacklist',bl?'yellow':'green',bl?'Detected':'No',lang);if(bl)score+=10}
    const hc=valKnown(g.holder_count)?Number(g.holder_count):null;
    if(hc!==null){addCheck(checks,'holders','Holders',hc<20?'yellow':'green',String(hc),lang);if(hc<20)score+=7}
    const bad=flag(g.malicious_address)||flag(g.is_malicious)||flag(g.fake_token);
    if(bad){addCheck(checks,'provider','GoPlus malicious-token flag','red','Detected',lang);score+=45;critical=true}
    addProvider(providers,'GoPlus',bad?'red':critical?'yellow':'green',bad?95:Math.min(80,score),'Token security');
  }
  if(hp){
    const r=hp.result||hp;
    const isHp=flag(r.isHoneypot)||String(r.honeypotResult?.isHoneypot||'').toLowerCase()==='true';
    const risk=String(r.riskLevel||r.risk||'').toLowerCase();
    if(isHp||risk==='high'){addCheck(checks,'honeypot','Honeypot.is','red',isHp?'Honeypot':'High risk',lang);score+=50;critical=true}
    else addCheck(checks,'honeypot','Honeypot.is','green','No honeypot flag',lang);
    addProvider(providers,'Honeypot.is',isHp||risk==='high'?'red':'green',isHp||risk==='high'?95:10,'Sellability simulation');
    securitySources.push('Honeypot.is');sources.push('Honeypot.is');
  }
  if(ts){
    securitySources.push('TokenSniffer');sources.push('TokenSniffer');
    const scam=String(ts.scam_status||ts.scamStatus||'').toLowerCase();
    const smell=Number(ts.score??ts.smell_test_results?.score);
    const bad=ts.is_scam===true||['scam','high_risk','high risk'].includes(scam);
    const s=bad?95:Number.isFinite(smell)?100-Math.max(0,Math.min(100,smell)):null;
    if(bad){addCheck(checks,'provider','TokenSniffer','red','SCAM',lang);score+=50;critical=true}
    else if(s!=null)addCheck(checks,'provider','TokenSniffer',s>=55?'yellow':'green',String(Math.round(s)),lang);
    addProvider(providers,'TokenSniffer',bad?'red':s>=55?'yellow':'green',s,bad?'Scam status':'Smell Test');
  }
  if(onchain){
    securitySources.push('Public EVM RPC');sources.push('Public EVM RPC');
    const ok=onchain.contract;
    addCheck(checks,'onchain','On-chain Contract','green',ok?`${onchain.bytecodeBytes} bytes`:'No bytecode',lang);
    if(!ok){score+=35;critical=true}
    addProvider(providers,'Public EVM RPC',ok?'green':'red',ok?5:90,`Bytecode + ERC-20 metadata`);
  }
  const addr=normalizeMaliciousAddress(addrSec);
  const dev=devAddress?{checked:!!addrSec,address:devAddress,malicious:addr?.malicious||false,reasons:addr?.reasons||[],source:addrSec?'GoPlus':null}:null;
  if(addr?.malicious){addCheck(checks,'dev','Dev Wallet Reputation','red',addr.reasons.join(', '),lang);score+=55;critical=true}
  if(devAddress){securitySources.push('Dev address reputation');sources.push('Dev address reputation')}
  if(!checks.length)addCheck(checks,'data','Security Data','gray','Unavailable',lang);
  score=Math.min(100,Math.max(0,Math.round(score)));
  const conf=confidence(securitySources.length);
  return{
    address,network:net.name,name,symbol,logo,isNew:market?.ageHours!=null&&market.ageHours<24,
    score:securitySources.length?score:null,level:finalLevel(securitySources.length?score:null,critical),
    confidence:conf.score,confidenceLabel:conf.label[lang],checks,providers,
    serviceStatus:[['GoPlus',!!g],['Honeypot.is',!!hp],['DexScreener',!!market],['TokenSniffer',!!ts],['Public EVM RPC',!!onchain],['Dev reputation',!!addrSec]].map(([name,available])=>({name,available})),
    dev,creator:null,market,sources,
    dataNotice:conf.score==='low'?{en:'Limited independent security data returned.',ru:'Вернулось мало независимых security-данных.',zh:'独立安全数据有限。'}[lang]:null
  };
}

async function checkSolana(address,net,lang,env){
  const [rc,gp,market,onchain]=await Promise.all([
    getJson(`https://api.rugcheck.xyz/v1/tokens/${encodeURIComponent(address)}/report`,{headers:authHeaders('rugcheck',env)}),
    getJson(`https://api.gopluslabs.io/api/v1/solana/token_security?contract_addresses=${encodeURIComponent(address)}`,{headers:authHeaders('goplus',env)}),
    fetchDex(address,'solana'),
    fetchSolanaOnchain(address,net.rpc)
  ]);
  const g=gp?.result?.[address]||gp?.result?.[Object.keys(gp?.result||{})[0]]||gp?.result||null;
  const checks=[],providers=[],sources=[],securitySources=[];let score=0,critical=false;
  let name=market?.name||'',symbol=market?.symbol||'',logo=market?.logo||null;

  if(rc){
    sources.push('RugCheck');securitySources.push('RugCheck');
    name=rc.tokenMeta?.name||rc.fileMeta?.name||name;
    symbol=rc.tokenMeta?.symbol||rc.fileMeta?.symbol||symbol;
    logo=rc.fileMeta?.image||logo;
  }
  if(g){sources.push('GoPlus Solana');securitySources.push('GoPlus Solana');name=g.token_name||name;symbol=g.token_symbol||symbol}
  if(market)sources.push('DexScreener');

  const mint=first(rc?.token?.mintAuthority,g?.mint_authority,onchain?.mintAuthority);
  const freeze=first(rc?.token?.freezeAuthority,g?.freeze_authority,onchain?.freezeAuthority);
  if(rc||g||onchain){
    addCheck(checks,'mint','Mint Authority',mint?'red':'green',mint?'Active':'Disabled',lang);
    if(mint){score+=22;critical=true}
    addCheck(checks,'freeze','Freeze Authority',freeze?'red':'green',freeze?'Active':'Disabled',lang);
    if(freeze){score+=18;critical=true}
  }
  if(onchain){
    securitySources.push('Public Solana RPC');sources.push('Public Solana RPC');
    if(onchain.top10Pct!=null){
      const st=onchain.top10Pct>50?'red':onchain.top10Pct>30?'yellow':'green';
      addCheck(checks,'holders','Top 10 Holders (on-chain)',st,`${onchain.top10Pct.toFixed(1)}%`,lang);
      if(onchain.top10Pct>50)score+=22;else if(onchain.top10Pct>30)score+=10;
    }
    const is2022=String(onchain.ownerProgram||'').includes('TokenzQd');
    if(is2022)addCheck(checks,'token2022','Token-2022','yellow','Extension program',lang);
    else addCheck(checks,'token2022','Token Program','green','SPL Token',lang);
    addProvider(providers,'Public Solana RPC','green',5,'Mint + supply + largest accounts');
  }
  const rcTop=rc?.topHolders?.length?rc.topHolders.slice(0,10).reduce((s,h)=>s+Number(h.pct||0),0):null;
  if(rcTop!=null&&!onchain?.top10Pct){
    const st=rcTop>50?'red':rcTop>30?'yellow':'green';
    addCheck(checks,'holders','Top 10 Holders',st,`${rcTop.toFixed(1)}%`,lang);
    if(rcTop>50)score+=22;else if(rcTop>30)score+=10;
  }
  const rcScore=Number(rc?.score_normalised);
  if(Number.isFinite(rcScore)){
    score=Math.max(score,Math.round(rcScore*.85));
    addProvider(providers,'RugCheck',rcScore>=55?'red':rcScore>=25?'yellow':'green',rcScore,`score_normalised ${rcScore}`);
  }
  if(rc?.risks?.length)rc.risks.slice(0,8).forEach(r=>{
    const danger=r.level==='danger'||r.level==='critical',warn=r.level==='warn'||r.level==='warning';
    addCheck(checks,'risk',r.name||'RugCheck risk',danger?'red':'yellow',r.value||r.description||'Flag',lang,r.description||localExplain('data',lang));
    score+=danger?9:warn?4:2;
    if(danger)critical=true;
  });
  if(g){
    const bad=flag(g.malicious_address)||flag(g.fake_token);
    if(bad){addCheck(checks,'provider','GoPlus malicious-token flag','red','Detected',lang);score+=45;critical=true}
    addProvider(providers,'GoPlus Solana',bad?'red':'green',bad?95:Math.min(55,score),'Token security');
  }
  const sell=await fetchJupiterSell(address,rc?.token?.supply,g?.decimals??rc?.token?.decimals);
  if(sell){
    securitySources.push('Jupiter Sell Route');sources.push('Jupiter Sell Route');
    if(sell.available){
      const impact=sell.priceImpactPct,st=impact!=null&&impact>20?'red':impact!=null&&impact>5?'yellow':'green';
      addCheck(checks,'sellroute','Sell Route',st,impact==null?'Route found':`Route found · ${impact.toFixed(2)}% impact`,lang);
      if(impact>20){score+=30;critical=true}else if(impact>5)score+=10;
      addProvider(providers,'Jupiter Sell Route',st,impact==null?5:Math.min(100,impact*3),'Public quote route');
    }else if(market?.liquidity){
      addCheck(checks,'sellroute','Sell Route','red','NO ROUTE',lang);score+=45;critical=true;
      addProvider(providers,'Jupiter Sell Route','red',95,'No route while DEX liquidity exists');
    }else{
      addCheck(checks,'sellroute','Sell Route','yellow','No route / no market',lang);
      addProvider(providers,'Jupiter Sell Route','yellow',55,'No route; market unavailable');
    }
  }
  const creator=rc?.creator||g?.creator_address||null;
  let dev=null,migration=null;
  if(creator){
    const[addrSec,history]=await Promise.all([fetchGoPlusAddress(creator,null,env),creatorMigrationHistory(creator,rc?.creatorTokens)]);
    const rep=normalizeMaliciousAddress(addrSec);
    dev={address:creator,checked:!!rep,malicious:rep?.malicious||false,reasons:rep?.reasons||[],source:rep?'GoPlus':null};
    if(addrSec)securitySources.push('Dev address reputation');
    if(rep?.malicious){addCheck(checks,'dev','Dev Wallet Reputation','red',rep.reasons.join(', '),lang);score+=60;critical=true}
    migration=history;
    if(history?.pct!=null){
      const st=history.pct>=50?'green':history.pct>=20?'yellow':'red';
      addCheck(checks,'migration','Dev DEX Migration',st,`${history.pct}% · ${history.migrated}/${history.known}`,lang);
      if(history.pct<20)score+=15;else if(history.pct<50)score+=7;
    }
  }
  if(!checks.length)addCheck(checks,'data','Security Data','gray','Unavailable',lang);
  score=Math.min(100,Math.max(0,Math.round(score)));
  const conf=confidence(securitySources.length);
  return{
    address,network:'Solana',name,symbol,logo,isNew:market?.ageHours!=null&&market.ageHours<24,
    score:securitySources.length?score:null,level:finalLevel(securitySources.length?score:null,critical),
    confidence:conf.score,confidenceLabel:conf.label[lang],checks,providers,
    serviceStatus:[['RugCheck',!!rc],['GoPlus Solana',!!g],['DexScreener',!!market],['Jupiter Sell Route',!!sell],['Public Solana RPC',!!onchain],['Dev reputation',!!dev?.checked],['Dev migration',!!migration?.known]].map(([name,available])=>({name,available})),
    dev,creatorHistory:migration,market,sources,
    dataNotice:conf.score==='low'?{en:'Limited independent security data returned.',ru:'Вернулось мало независимых security-данных.',zh:'独立安全数据有限。'}[lang]:null
  };
}

function buildChartUrl(result,network,address,net){return result.market?.pairUrl||net.gmgn(address)}

async function handleCheck(request,env){
  const url=new URL(request.url);
  const p=Object.fromEntries(url.searchParams);
  const address=(p.address||"").trim();
  const network=(p.network||"solana").toLowerCase();
  const lang=["en","ru","zh"].includes((p.lang||"en").toLowerCase())?(p.lang||"en").toLowerCase():"en";
  const net=NETWORKS[network];
  if(!net)return json(400,{error:"Unsupported network"});
  if((network==="solana"&&!isSolana(address))||(network!=="solana"&&!isEvm(address)))return json(400,{error:"Invalid address"});
  try{
    const result=network==="solana"?await checkSolana(address,net,lang,env):await checkEVM(address,net,lang,env);
    result.address=address;
    result.network=net.name;
    result.explorerUrl=net.explorer(address);
    result.chartUrl=buildChartUrl(result,network,address,net);
    return json(200,result);
  }catch(e){
    return json(200,{
      address,network:net.name,name:"",symbol:"",logo:null,isNew:false,score:null,level:"yellow",
      confidence:"low",confidenceLabel:{en:"Low",ru:"Низкая",zh:"低"}[lang],
      checks:[{id:"data",label:"Security data",status:"gray",value:"Unavailable",explain:localExplain("data",lang)}],
      providers:[],serviceStatus:[],dev:null,market:null,sources:[],
      dataNotice:{en:"Security providers returned incomplete data.",ru:"Security-сервисы вернули неполные данные.",zh:"安全服务返回的数据不完整。"}[lang]
    });
  }
}

// ============================================================
// SCREENER — v19.1 (8 ratio filters + sort by firstSeenAt)
// ============================================================
const MODES = {
  showcase: { id: 'showcase', mc: [5000, 500000],  liq: 500,   age: [0.25, 168], volLiqMin: 0.1, vol1hMin: 100,  vol1hRatio: 0.01, vol5mMin: 50,   tx5mMin: 1,  bsRatio: 0.8,  chgRange: [-60, 200], minAccel: 0 },
  degen:    { id: 'degen',    mc: [10000, 300000],  liq: 2000,  age: [0.5, 72],   volLiqMin: 0.5, vol1hMin: 300,  vol1hRatio: 0.05, vol5mMin: 200,  tx5mMin: 3,  bsRatio: 1.2,  chgRange: [-30, 100], minAccel: 1.5 },
  sniper:   { id: 'sniper',   mc: [20000, 200000],  liq: 5000,  age: [1, 48],     volLiqMin: 1.5, vol1hMin: 1000, vol1hRatio: 0.15, vol5mMin: 500,  tx5mMin: 10, bsRatio: 1.5,  chgRange: [-15, 50],  minAccel: 2.0 }
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
  const accel = num(t.volumeAccel) || 0;

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
  if (accel < m.minAccel) return false;
  return true;
}

function shouldSkipToken(t) {
  const age = num(t.ageHours) || 0;
  const mc = num(t.marketCap) || 0;
  const liq = num(t.liquidity) || 0;
  const vol1h = num(t.volume1h) || 0;
  const vol24 = num(t.volume24h) || 0;
  const buys1h = num(t.buys1h) || 0;
  const sells1h = num(t.sells1h) || 0;
  const tx1h = buys1h + sells1h;
  const buys5m = num(t.buys5m) || 0;
  const sells5m = num(t.sells5m) || 0;
  const tx5m = buys5m + sells5m;
  const holders = num(t.holders) || 0;

  if (tx5m >= 20 && tx1h > 0 && tx5m / tx1h > 0.6) return 'botPattern';
  if (tx1h > 0 && mc > 50000) {
    const avgTxSize = vol1h / tx1h;
    if (avgTxSize < 50) return 'dustTrading';
  }
  if (mc > 0 && vol24 > 0) {
    const turnover = vol24 / mc;
    if (turnover < 0.15) return 'deadVolume';
  }
  if (tx1h > 0 && buys1h / tx1h > 0.75 && tx1h >= 50) return 'buyAsymmetry';
  if (liq > 0 && vol24 / liq > 20) return 'fakeTurnover';
  if (mc > 0 && vol1h > 0) {
    const hourlyTurnover = vol1h / mc;
    if (hourlyTurnover < 0.005) return 'deadHourly';
  }
  if (liq > 0 && mc / liq > 30) return 'thinPool';
  if (holders > 0 && tx1h / holders > 1.0) return 'churnHolders';
  if (tx1h > 0 && mc > 50000) {
    const avgTxSize = vol1h / tx1h;
    if (avgTxSize < 50 && tx1h > 200) return 'noWhaleActivity';
  }
  if (age < 1 && buys1h >= 100 && (sells1h === 0 ? 10 : buys1h / sells1h) > 5) return 'sniperWave';
  if (age < 0.15) return 'tooFresh';
  return null;
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
  const buys5m = num(t.buys5m) || 0, sells5m = num(t.sells5m) || 0;
  const accel = num(t.volumeAccel) || 0;
  let s = 0;
  if (vol24 > 0) { const r = vol1h / vol24; if (r >= 0.5) s += 15; else if (r >= 0.3) s += 10; else if (r >= 0.15) s += 5; }
  if (accel >= 5) s += 10; else if (accel >= 3) s += 7; else if (accel >= 1.5) s += 4; else if (vol5m >= 15000) s += 2;
  if (tx5m >= 60) s += 5; else if (tx5m >= 30) s += 3; else if (tx5m >= 20) s += 1;
  if (sells1h > 0) {
    const r = buys1h / sells1h;
    if (r >= 3.0) s += 15;
    else if (r >= 2.5) s += 12;
    else if (r >= 2.0) s += 10;
    else if (r >= 1.5) s += 5;
  } else if (buys1h > 0) s += 15;
  if (sells5m > 0 && sells1h > 0) {
    const r5m = buys5m / sells5m;
    const r1h = buys1h / sells1h;
    if (r5m > r1h * 1.3) s += 5;
  }
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
  const safety = scoreSafety(t);
  const momentum = scoreMomentum(t);
  const smart = scoreSmart(t, smartSet);
  const total = clamp(safety + momentum + smart.score, 0, 100);
  let tier = 'low';
  if (total >= 70) tier = 'high';
  else if (total >= 40) tier = 'mid';
  return { total, tier, safety, momentum, smart: smart.score, smartFlag: smart.flag };
}

function mapPair(p) {
  const base = p.baseToken || {};
  const age = sAgeHours(p.pairCreatedAt);
  const buys1h = num(p.txns?.h1?.buys) || 0;
  const sells1h = num(p.txns?.h1?.sells) || 0;
  const buys5m = num(p.txns?.m5?.buys) || 0;
  const sells5m = num(p.txns?.m5?.sells) || 0;
  const vol1h = num(p.volume?.h1) || 0;
  const vol5m = num(p.volume?.m5) || 0;
  const vol1hAvg5m = vol1h / 12;
  const volumeAccel = vol1hAvg5m > 0 ? vol5m / vol1hAvg5m : 0;
  return {
    address: base.address,
    name: base.name || '—',
    symbol: base.symbol || '—',
    priceUsd: num(p.priceUsd),
    priceChange1h: num(p.priceChange?.h1),
    priceChange24h: num(p.priceChange?.h24),
    liquidity: num(p.liquidity?.usd),
    volume24h: num(p.volume?.h24),
    volume1h: vol1h,
    volume5m: vol5m,
    volumeAccel: Math.round(volumeAccel * 100) / 100,
    marketCap: num(p.marketCap) ?? num(p.fdv),
    holders: num(p.holders),
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

async function buildScreenerData(env, mode) {
  const pairs = await fetchDexScreenerAll();
  const seen = new Set();
  const merged = [];
  const skipStats = {
    botPattern: 0, dustTrading: 0, deadVolume: 0, buyAsymmetry: 0,
    fakeTurnover: 0, deadHourly: 0, thinPool: 0, churnHolders: 0,
    noWhaleActivity: 0, sniperWave: 0, tooFresh: 0,
    totalSkipped: 0, shown: 0
  };

  for (const p of pairs) {
    const addr = p.baseToken?.address;
    if (!addr || seen.has(addr)) continue;
    seen.add(addr);
    const token = mapPair(p);
    const skipReason = shouldSkipToken(token);
    if (skipReason) {
      skipStats[skipReason] = (skipStats[skipReason] || 0) + 1;
      skipStats.totalSkipped++;
      continue;
    }
    merged.push(token);
  }

  const smart = await getSmartWallets(env);
  const smartSet = smart?.wallets?.length ? new Set(smart.wallets.map(w => w.address)) : null;

  // Load seen map to get firstSeenAt
  const seenMap = await getSeenTokens(env);
  const now = Date.now();

  // Attach firstSeenAt for each token; update if new
  for (const t of merged) {
    const existing = seenMap.get(t.address);
    if (existing) {
      if (!existing.firstSeenAt) existing.firstSeenAt = now;
      t.firstSeenAt = existing.firstSeenAt;
      if (!existing.modes.includes(mode)) existing.modes.push(mode);
    } else {
      const entry = { modes: [mode], firstSeenAt: now };
      seenMap.set(t.address, entry);
      t.firstSeenAt = now;
    }
  }
  await saveSeenTokens(env, seenMap);

  const filtered = merged
    .filter(t => passesFilters(t, mode))
    .map(t => ({
      ...t,
      firstSeenAgo: Math.floor((now - (t.firstSeenAt || now)) / 1000),
      degen: computeDegenScore(t, smartSet)
    }))
    .sort((a, b) => (b.firstSeenAt || 0) - (a.firstSeenAt || 0))
    .slice(0, 40);

  skipStats.shown = filtered.length;
  return { filtered, smart, skipStats };
}

async function handleScreener(request, env) {
  try {
    const url = new URL(request.url);
    const mode = (url.searchParams.get('mode') || 'showcase').toLowerCase();
    const validMode = MODES[mode] ? mode : 'showcase';
    const { filtered, smart, skipStats } = await buildScreenerData(env, validMode);

    return json(200, {
      updatedAt: new Date().toISOString(),
      mode: validMode,
      count: filtered.length,
      smartWallets: smart?.wallets?.length || 0,
      skipStats,
      tokens: filtered
    });
  } catch (e) {
    return json(500, { error: 'Screener error', detail: String(e?.message || e) });
  }
}

// ============================================================
// CRON — не сохраняем firstSeenAt для токенов, найденных только в CRON
// (чтобы только пользовательский запрос фиксировал firstSeenAt)
// ============================================================
async function runCron(env) {
  const subs = await getSubscriptions(env);
  if (!subs.length) return;

  const smart = await getSmartWallets(env);
  const smartSet = smart?.wallets?.length ? new Set(smart.wallets.map(w => w.address)) : null;

  const pairs = await fetchDexScreenerAll();
  const seen = new Set();
  const merged = [];
  for (const p of pairs) {
    const addr = p.baseToken?.address;
    if (!addr || seen.has(addr)) continue;
    seen.add(addr);
    const token = mapPair(p);
    if (shouldSkipToken(token)) continue;
    merged.push(token);
  }

  // Send push for new tokens in sniper mode only
  const sniperMatches = merged.filter(t => passesFilters(t, 'sniper')).map(t => ({ ...t, degen: computeDegenScore(t, smartSet) }));
  if (!sniperMatches.length) return;

  const seenMap = await getSeenTokens(env);
  let sentSomething = false;
  for (const t of sniperMatches) {
    const existing = seenMap.get(t.address);
    if (!existing) {
      // New token — notify and mark (with firstSeenAt)
      seenMap.set(t.address, { modes: ['sniper'], firstSeenAt: Date.now() });
      if (!sentSomething && t.degen?.smartFlag) {
        const payload = {
          title: `🔴 Sniper · $${t.symbol} 🐋`,
          body: `MC $${Math.round((t.marketCap || 0) / 1000)}K · Accel ${t.volumeAccel}x · Age ${t.ageHours?.toFixed(1)}h`,
          icon: t.logo || '/icon-192.png',
          tag: 'dobe-sniper-' + t.address.slice(0, 8),
          url: '/screener?mode=sniper'
        };
        for (const sub of subs) { sendPush(sub, payload, env).catch(() => {}); }
        sentSomething = true;
      }
    }
  }
  await saveSeenTokens(env, seenMap);
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
