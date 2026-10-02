// DOBE Scan — unified Worker (check + screener + static assets)

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
      signal: AbortSignal.timeout(8500),
      headers: { accept: 'application/json', ...(opts.headers || {}) }
    });
    if (!r.ok) return null;
    return await r.json();
  } catch {
    return null;
  }
}

async function postJson(url, body, opts = {}) {
  try {
    const r = await fetch(url, {
      ...opts,
      method: 'POST',
      signal: AbortSignal.timeout(8500),
      headers: { 'content-type': 'application/json', accept: 'application/json', ...(opts.headers || {}) },
      body: JSON.stringify(body)
    });
    if (!r.ok) return null;
    return await r.json();
  } catch {
    return null;
  }
}

// ============================================================
// CHECK LOGIC
// ============================================================
const NETWORKS = {
  solana: { name: 'Solana', ds: 'solana', explorer: a => `https://solscan.io/token/${a}`, gmgn: a => `https://gmgn.ai/sol/token/${a}`, rpc: 'https://api.mainnet-beta.solana.com' },
  base: { name: 'Base', chainId: '8453', ds: 'base', explorer: a => `https://basescan.org/token/${a}`, gmgn: a => `https://gmgn.ai/base/token/${a}`, rpc: 'https://mainnet.base.org' },
  bsc: { name: 'BSC', chainId: '56', ds: 'bsc', explorer: a => `https://bscscan.com/token/${a}`, gmgn: a => `https://gmgn.ai/bsc/token/${a}`, rpc: 'https://bsc-dataseed.binance.org' },
  ethereum: { name: 'Ethereum', chainId: '1', ds: 'ethereum', explorer: a => `https://etherscan.io/token/${a}`, gmgn: a => `https://gmgn.ai/eth/token/${a}`, rpc: 'https://cloudflare-eth.com' },
  arbitrum: { name: 'Arbitrum', chainId: '42161', ds: 'arbitrum', explorer: a => `https://arbiscan.io/token/${a}`, gmgn: a => `https://gmgn.ai/arbitrum/token/${a}`, rpc: 'https://arb1.arbitrum.io/rpc' },
  polygon: { name: 'Polygon', chainId: '137', ds: 'polygon', explorer: a => `https://polygonscan.com/token/${a}`, gmgn: a => `https://gmgn.ai/polygon/token/${a}`, rpc: 'https://polygon-rpc.com' },
  avalanche: { name: 'Avalanche', chainId: '43114', ds: 'avalanche', explorer: a => `https://snowtrace.io/token/${a}`, gmgn: a => `https://gmgn.ai/avax/token/${a}`, rpc: 'https://api.avax.network/ext/bc/C/rpc' },
  optimism: { name: 'Optimism', chainId: '10', ds: 'optimism', explorer: a => `https://optimistic.etherscan.io/token/${a}`, gmgn: a => `https://gmgn.ai/optimism/token/${a}`, rpc: 'https://mainnet.optimism.io' },
};

const EXPLAIN = {
  honeypot:{en:'A security provider detected a honeypot or sell restriction.',ru:'Security-сервис обнаружил honeypot или ограничение продажи.',zh:'安全服务检测到蜜罐或卖出限制。'},
  ownership:{en:'Owner/admin control remains. Check what privileged accounts can change.',ru:'У владельца/админа остаётся контроль. Важно, что именно он может менять.',zh:'所有者/管理员仍有控制权。请检查其可修改的内容。'},
  mintable:{en:'Mint authority can increase supply.',ru:'Mint authority может увеличить supply.',zh:'铸币权限可以增加供应量。'},
  tax:{en:'Reported buy/sell tax. High or asymmetric tax can make trading difficult.',ru:'Заявленный buy/sell tax. Высокий или асимметричный налог может мешать торговле.',zh:'报告的买卖税。高税率可能影响交易。'},
  proxy:{en:'Upgradeable/proxy logic can change later through privileged controls.',ru:'Upgradeable/proxy-логика может быть изменена через привилегированные права.',zh:'可升级/代理逻辑可能通过特权权限改变。'},
  verified:{en:'Verified/open-source code improves transparency.',ru:'Верифицированный/open-source код повышает прозрачность.',zh:'已验证/开源代码提高透明度。'},
  holders:{en:'Holder concentration can create sell-pressure or coordinated-exit risk.',ru:'Концентрация холдеров создаёт риск давления продаж или координированного выхода.',zh:'持仓集中可能带来抛压或协同退出风险。'},
  blacklist:{en:'Blacklist capability can restrict selected addresses.',ru:'Blacklist может ограничивать отдельные адреса.',zh:'黑名单功能可能限制特定地址。'},
  pause:{en:'Transfers may be paused by an administrator.',ru:'Администратор потенциально может остановить переводы.',zh:'管理员可能暂停转账。'},
  modTax:{en:'Tax appears changeable through contract permissions.',ru:'Налог можно менять через права контракта.',zh:'税率可能通过合约权限修改。'},
  sellroute:{en:'A live DEX route checks whether the token can currently be sold. No route can also mean missing liquidity.',ru:'Живой DEX-маршрут проверяет, можно ли сейчас продать токен. Нет маршрута также бывает при отсутствии ликвидности.',zh:'实时 DEX 路由检查代币当前是否可卖。无路由也可能是缺少流动性。'},
  dev:{en:'Developer/deployer reputation is a separate risk layer.',ru:'Репутация dev/deployer — отдельный слой риска.',zh:'开发者/部署者信誉是独立风险层。'},
  migration:{en:'Historical DEX migration behavior of this developer; not a guarantee.',ru:'История выхода токенов этого dev на DEX; это не гарантия для текущего токена.',zh:'该开发者历史代币进入 DEX 的情况，不代表当前代币。'},
  onchain:{en:'Direct blockchain data. Public RPC is used without a private API key.',ru:'Прямые данные блокчейна. Используется публичный RPC без приватного API-ключа.',zh:'直接链上数据。使用无需私钥的公共 RPC。'},
  token2022:{en:'Solana Token-2022 extensions can add transfer or account controls that need review.',ru:'Расширения Solana Token-2022 могут добавлять дополнительные правила переводов/аккаунтов.',zh:'Solana Token-2022 扩展可能增加转账或账户控制。'},
  data:{en:'This source returned insufficient data. Missing data is never treated as safe.',ru:'Источник вернул недостаточно данных. Отсутствие данных никогда не считается безопасностью.',zh:'该来源数据不足。缺失数据不会被视为安全。'},
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

async function fetchDex(address,chain){const d=await getJson(`https://api.dexscreener.com/latest/dex/tokens/${encodeURIComponent(address)}`);if(!d?.pairs?.length)return null;let ps=d.pairs.filter(p=>!chain||p.chainId===chain);if(!ps.length)ps=d.pairs;ps.sort((a,b)=>(b.liquidity?.usd||0)-(a.liquidity?.usd||0));const p=ps[0],tx=p.txns?.h24||{},created=p.pairCreatedAt?Number(p.pairCreatedAt):null;return{priceUsd:p.priceUsd,priceChange24h:p.priceChange?.h24,liquidity:p.liquidity?.usd,volume24h:p.volume?.h24,fdv:p.fdv,pairUrl:p.url,dex:p.dexId,pairCreatedAt:created,ageHours:created?(Date.now()-created)/36e5:null,logo:p.info?.imageUrl||null,name:p.baseToken?.name,symbol:p.baseToken?.symbol,buys24h:tx.buys||0,sells24h:tx.sells||0,txns24h:(tx.buys||0)+(tx.sells||0),pairAddress:p.pairAddress||null}}

async function fetchJupiterSell(address,supply,decimals){if(!supply||!Number.isFinite(Number(decimals)))return null;let raw;try{raw=BigInt(String(supply))}catch{return null}const d=Math.max(0,Math.min(18,Number(decimals)));let amount=raw/10000n;const min=10n**BigInt(Math.min(d,6));if(amount<min)amount=min;const urls=[`https://lite-api.jup.ag/swap/v1/quote?inputMint=${encodeURIComponent(address)}&outputMint=So11111111111111111111111111111111111111112&amount=${amount}&slippageBps=1500&restrictIntermediateTokens=true`,`https://quote-api.jup.ag/v6/quote?inputMint=${encodeURIComponent(address)}&outputMint=So11111111111111111111111111111111111111112&amount=${amount}&slippageBps=1500`];for(const u of urls){const q=await getJson(u);if(q)return{available:true,amount:amount.toString(),outAmount:q.outAmount||null,priceImpactPct:valKnown(q.priceImpactPct)?Number(q.priceImpactPct):null,routeCount:Array.isArray(q.routePlan)?q.routePlan.length:null}}return{available:false,amount:amount.toString(),outAmount:null,priceImpactPct:null,routeCount:0}}

async function fetchGoPlusAddress(address,chainId,env){const d=await getJson(`https://api.gopluslabs.io/api/v1/address_security/${encodeURIComponent(address)}${chainId?`?chain_id=${encodeURIComponent(chainId)}`:''}`,{headers:authHeaders('goplus',env)});return d?.result||null}
function normalizeMaliciousAddress(a){if(!a)return null;const reasons=[];if(flag(a.honeypot_related_address)||flag(a.malicious_address))reasons.push('scam/honeypot');if(flag(a.phishing_activities))reasons.push('phishing');if(flag(a.stealing_attack))reasons.push('stealing');if(flag(a.blackmail_activities))reasons.push('blackmail');if(flag(a.cybercrime))reasons.push('cybercrime');if(flag(a.sanctioned))reasons.push('sanctioned');const count=Number(a.number_of_malicious_contracts_created||0);if(count>0)reasons.push(`${count} malicious contracts`);return{checked:true,malicious:reasons.length>0,reasons,raw:a}}

async function fetchPumpCoin(mint){for(const u of [`https://frontend-api-v3.pump.fun/coins-v2/${encodeURIComponent(mint)}`,`https://frontend-api-v3.pump.fun/coins/${encodeURIComponent(mint)}?sync=true`]){const d=await getJson(u);if(d)return d}return null}
async function creatorMigrationHistory(creator,creatorTokens){if(!creator)return null;let tokens=Array.isArray(creatorTokens)?creatorTokens.slice(0,30):[];if(!tokens.length){const d=await getJson(`https://frontend-api-v3.pump.fun/coins/user-created-coins/${encodeURIComponent(creator)}?offset=0&limit=30&includeNsfw=false`);if(Array.isArray(d))tokens=d.slice(0,30);else if(Array.isArray(d?.coins))tokens=d.coins.slice(0,30)}if(!tokens.length)return{creator,total:0,migrated:0,pct:null,known:0,source:'Pump.fun + DexScreener'};const details=[];let idx=0;const workers=Array.from({length:5},async()=>{while(idx<tokens.length){const i=idx++,t=tokens[i]||{},mint=t.mint||t.address;const[d,dx]=await Promise.all([mint?fetchPumpCoin(mint):Promise.resolve(null),mint?fetchDex(mint,'solana'):Promise.resolve(null)]);const complete=d?.complete??t.complete??null,pool=d?.raydium_pool||d?.pump_swap_pool||d?.raydiumPool||t.raydium_pool||null,hasDexPair=!!dx?.pairAddress||!!dx?.pairUrl;details[i]={mint,complete,pool,hasDexPair}}});await Promise.all(workers);const known=details.filter(x=>x&&((x.complete!==null)||x.hasDexPair)).length,migrated=details.filter(x=>x&&(x.complete===true||!!x.pool||x.hasDexPair)).length;return{creator,total:details.length,migrated,pct:known?Math.round(migrated/known*1000)/10:null,known,source:'Pump.fun + DexScreener'}}

async function solanaRpc(rpc,method,params=[]){return postJson(rpc,{jsonrpc:'2.0',id:1,method,params})}
async function fetchSolanaOnchain(address,rpc){const [ai,supply,largest]=await Promise.all([solanaRpc(rpc,'getAccountInfo',[address,{encoding:'jsonParsed',commitment:'confirmed'}]),solanaRpc(rpc,'getTokenSupply',[address,{commitment:'confirmed'}]),solanaRpc(rpc,'getTokenLargestAccounts',[address,{commitment:'confirmed'}])]);const info=ai?.result?.value, parsed=info?.data?.parsed?.info||null, s=supply?.result?.value||null, ls=largest?.result?.value||[];if(!info&&!s&&!ls.length)return null;let top10=null;if(s?.uiAmount&&ls.length)top10=ls.slice(0,10).reduce((a,x)=>a+Number(x.uiAmount||0),0)/Number(s.uiAmount)*100;return{exists:!!info,ownerProgram:info?.owner||null,mintAuthority:parsed?.mintAuthority||null,freezeAuthority:parsed?.freezeAuthority||null,decimals:parsed?.decimals??s?.decimals??null,supply:s?.amount||null,uiSupply:s?.uiAmount||null,top10Pct:Number.isFinite(top10)?top10:null,largest:ls.slice(0,10).map(x=>({address:x.address,amount:x.amount,uiAmount:x.uiAmount}))}}

const EVM_SELECTORS={name:'0x06fdde03',symbol:'0x95d89b41',decimals:'0x313ce567',totalSupply:'0x18160ddd'};
function decodeUint(hex){try{return hex?Number(BigInt(hex)):null}catch{return null}}
function decodeString(hex){if(!hex||hex==='0x')return null;try{const h=hex.slice(2);if(h.length>=128){const offset=Number(BigInt('0x'+h.slice(0,64)));const start=offset*2;const len=Number(BigInt('0x'+h.slice(start,start+64)));const data=h.slice(start+64,start+64+len*2);return atob(data).replace(/\0/g,'')}return atob(h).replace(/\0/g,'')}catch{return null}}
async function evmCall(rpc,to,data){const d=await postJson(rpc,{jsonrpc:'2.0',id:1,method:'eth_call',params:[{to,data},'latest']});return d?.result||null}
async function fetchEvmOnchain(address,rpc){const [code,name,symbol,decimals,supply]=await Promise.all([postJson(rpc,{jsonrpc:'2.0',id:1,method:'eth_getCode',params:[address,'latest']}),evmCall(rpc,address,EVM_SELECTORS.name),evmCall(rpc,address,EVM_SELECTORS.symbol),evmCall(rpc,address,EVM_SELECTORS.decimals),evmCall(rpc,address,EVM_SELECTORS.totalSupply)]);const bytecode=code?.result;if(!bytecode)return null;return{contract:bytecode!=='0x',bytecodeBytes:bytecode&&bytecode!=='0x'?(bytecode.length-2)/2:0,name:decodeString(name),symbol:decodeString(symbol),decimals:decodeUint(decimals),totalSupply:supply?String(BigInt(supply)):null}}

async function fetchHoneypot(address,chainId){if(!['1','56','8453'].includes(chainId))return null;return getJson(`https://api.honeypot.is/v2/IsHoneypot?address=${encodeURIComponent(address)}&chainID=${encodeURIComponent(chainId)}`)}
async function fetchTokenSniffer(address,chainId,env){if(!env?.TOKENSNIFFER_API_KEY)return null;return getJson(`https://tokensniffer.com/api/v2/tokens/${chainId}/${encodeURIComponent(address)}?include_metrics=true&include_tests=true&include_similar=true`,{headers:{'X-API-Key':env.TOKENSNIFFER_API_KEY}})}

async function checkEVM(address,net,lang,env){
  const [gp,hp,market,ts,onchain]=await Promise.all([getJson(`https://api.gopluslabs.io/api/v1/token_security/${net.chainId}?contract_addresses=${encodeURIComponent(address)}`,{headers:authHeaders('goplus',env)}),fetchHoneypot(address,net.chainId),fetchDex(address,net.ds),fetchTokenSniffer(address,net.chainId,env),fetchEvmOnchain(address,net.rpc)]);
  const g=gp?.result?.[address.toLowerCase()]||gp?.result?.[Object.keys(gp?.result||{})[0]]||null;const devAddress=g?.creator_address||g?.owner_address||null;const addrSec=devAddress?await fetchGoPlusAddress(devAddress,net.chainId,env):null;const checks=[],providers=[],sources=[],securitySources=[];let score=0,critical=false,name=market?.name||onchain?.name||'',symbol=market?.symbol||onchain?.symbol||'',logo=market?.logo||null;
  if(g){sources.push('GoPlus');securitySources.push('GoPlus');const honeypot=flag(g.is_honeypot);if(honeypot){addCheck(checks,'honeypot','Honeypot','red','Detected',lang);score+=55;critical=true}else addCheck(checks,'honeypot','Honeypot','green','Not detected',lang);const open=flag(g.is_open_source);addCheck(checks,'verified','Open Source','green',open?'Yes':'No',lang);if(!open)score+=5;const mint=flag(g.is_mintable);addCheck(checks,'mintable','Mintable','red',mint?'Yes':'No',lang);if(mint){score+=22;critical=true}const proxy=flag(g.is_proxy);addCheck(checks,'proxy','Proxy / Upgradeable',proxy?'yellow':'green',proxy?'Yes':'No',lang);if(proxy)score+=8;const owner=valKnown(g.owner_address)?g.owner_address:null;if(owner){const renounced=/^0x0{40}$/i.test(owner)||/^0x0{64}$/i.test(owner);addCheck(checks,'ownership','Owner Control',renounced?'green':'yellow',renounced?'Renounced':'Present',lang);if(!renounced)score+=6}const buyTax=pct(g.buy_tax),sellTax=pct(g.sell_tax);if(buyTax!==null||sellTax!==null){const mx=Math.max(buyTax||0,sellTax||0),st=mx>15?'red':mx>5?'yellow':'green';addCheck(checks,'tax','Buy / Sell Tax',st,`${(buyTax??0).toFixed(1)}% / ${(sellTax??0).toFixed(1)}%`,lang);if(mx>15){score+=25;critical=true}else if(mx>5)score+=10}if(valKnown(g.slippage_modifiable)){const x=flag(g.slippage_modifiable);addCheck(checks,'modTax','Tax Modifiable',x?'yellow':'green',x?'Yes':'No',lang);if(x)score+=10}if(valKnown(g.transfer_pausable)){const x=flag(g.transfer_pausable);addCheck(checks,'pause','Trading Pausable',x?'red':'green',x?'Yes':'No',lang);if(x){score+=15;critical=true}}const bl=valKnown(g.is_blacklisted)?flag(g.is_blacklisted):null;if(bl!==null){addCheck(checks,'blacklist','Blacklist',bl?'yellow':'green',bl?'Detected':'No',lang);if(bl)score+=10}const hc=valKnown(g.holder_count)?Number(g.holder_count):null;if(hc!==null){addCheck(checks,'holders','Holders',hc<20?'yellow':'green',String(hc),lang);if(hc<20)score+=7}const bad=flag(g.malicious_address)||flag(g.is_malicious)||flag(g.fake_token);if(bad){addCheck(checks,'provider','GoPlus malicious-token flag','red','Detected',lang);score+=45;critical=true}addProvider(providers,'GoPlus',bad?'red':critical?'yellow':'green',bad?95:Math.min(80,score),'Token security')}
  if(hp){const r=hp.result||hp;const isHp=flag(r.isHoneypot)||String(r.honeypotResult?.isHoneypot||'').toLowerCase()==='true';const risk=String(r.riskLevel||r.risk||'').toLowerCase();if(isHp||risk==='high'){addCheck(checks,'honeypot','Honeypot.is','red',isHp?'Honeypot':'High risk',lang);score+=50;critical=true}else addCheck(checks,'honeypot','Honeypot.is','green','No honeypot flag',lang);addProvider(providers,'Honeypot.is',isHp||risk==='high'?'red':'green',isHp||risk==='high'?95:10,'Sellability simulation') ;securitySources.push('Honeypot.is');sources.push('Honeypot.is')}
  if(ts){securitySources.push('TokenSniffer');sources.push('TokenSniffer');const scam=String(ts.scam_status||ts.scamStatus||'').toLowerCase();const smell=Number(ts.score??ts.smell_test_results?.score);const bad=ts.is_scam===true||['scam','high_risk','high risk'].includes(scam);const s=bad?95:Number.isFinite(smell)?100-Math.max(0,Math.min(100,smell)):null;if(bad){addCheck(checks,'provider','TokenSniffer','red','SCAM',lang);score+=50;critical=true}else if(s!=null)addCheck(checks,'provider','TokenSniffer',s>=55?'yellow':'green',String(Math.round(s)),lang);addProvider(providers,'TokenSniffer',bad?'red':s>=55?'yellow':'green',s,bad?'Scam status':'Smell Test')}
  if(onchain){securitySources.push('Public EVM RPC');sources.push('Public EVM RPC');const ok=onchain.contract;addCheck(checks,'onchain','On-chain Contract','green',ok?`${onchain.bytecodeBytes} bytes`:'No bytecode',lang);if(!ok){score+=35;critical=true}addProvider(providers,'Public EVM RPC',ok?'green':'red',ok?5:90,`Bytecode + ERC-20 metadata`)}
  const addr=normalizeMaliciousAddress(addrSec);const dev=devAddress?{checked:!!addrSec,address:devAddress,malicious:addr?.malicious||false,reasons:addr?.reasons||[],source:addrSec?'GoPlus':null}:null;if(addr?.malicious){addCheck(checks,'dev','Dev Wallet Reputation','red',addr.reasons.join(', '),lang);score+=55;critical=true}if(devAddress){securitySources.push('Dev address reputation');sources.push('Dev address reputation')}
  if(!checks.length)addCheck(checks,'data','Security Data','gray','Unavailable',lang);score=Math.min(100,Math.max(0,Math.round(score)));const conf=confidence(securitySources.length);return{address,network:net.name,name,symbol,logo,isNew:market?.ageHours!=null&&market.ageHours<24,score:securitySources.length?score:null,level:finalLevel(securitySources.length?score:null,critical),confidence:conf.score,confidenceLabel:conf.label[lang],checks,providers,serviceStatus:[['GoPlus',!!g],['Honeypot.is',!!hp],['DexScreener',!!market],['TokenSniffer',!!ts],['Public EVM RPC',!!onchain],['Dev reputation',!!addrSec]].map(([name,available])=>({name,available})),dev,creator:null,market,sources,dataNotice:conf.score==='low'?{en:'Limited independent security data returned. Unknown data is not treated as safe.',ru:'Вернулось мало независимых security-данных. Неизвестные данные не считаются безопасными.',zh:'独立安全数据有限。未知数据不会被视为安全。'}[lang]:null}}

async function checkSolana(address,net,lang,env){
  const [rc,gp,market,onchain]=await Promise.all([getJson(`https://api.rugcheck.xyz/v1/tokens/${encodeURIComponent(address)}/report`,{headers:authHeaders('rugcheck',env)}),getJson(`https://api.gopluslabs.io/api/v1/solana/token_security?contract_addresses=${encodeURIComponent(address)}`,{headers:authHeaders('goplus',env)}),fetchDex(address,'solana'),fetchSolanaOnchain(address,net.rpc)]);
  const g=gp?.result?.[address]||gp?.result?.[Object.keys(gp?.result||{})[0]]||gp?.result||null;const checks=[],providers=[],sources=[],securitySources=[];let score=0,critical=false,name=market?.name||'',symbol=market?.symbol||'',logo=market?.logo||null;
  if(rc){sources.push('RugCheck');securitySources.push('RugCheck');name=rc.tokenMeta?.name||rc.fileMeta?.name||name;symbol=rc.tokenMeta?.symbol||rc.fileMeta?.symbol||symbol;logo=rc.fileMeta?.image||logo}
  if(g){sources.push('GoPlus Solana');securitySources.push('GoPlus Solana');name=g.token_name||name;symbol=g.token_symbol||symbol}
  if(market)sources.push('DexScreener');
  const mint=first(rc?.token?.mintAuthority,g?.mint_authority,onchain?.mintAuthority),freeze=first(rc?.token?.freezeAuthority,g?.freeze_authority,onchain?.freezeAuthority);if(rc||g||onchain){addCheck(checks,'mint','Mint Authority',mint?'red':'green',mint?'Active':'Disabled',lang);if(mint){score+=22;critical=true}addCheck(checks,'freeze','Freeze Authority',freeze?'red':'green',freeze?'Active':'Disabled',lang);if(freeze){score+=18;critical=true}}
  if(onchain){securitySources.push('Public Solana RPC');sources.push('Public Solana RPC');if(onchain.top10Pct!=null){const st=onchain.top10Pct>50?'red':onchain.top10Pct>30?'yellow':'green';addCheck(checks,'holders','Top 10 Holders (on-chain)',st,`${onchain.top10Pct.toFixed(1)}%`,lang);if(onchain.top10Pct>50)score+=22;else if(onchain.top10Pct>30)score+=10}const is2022=String(onchain.ownerProgram||'').includes('TokenzQd');if(is2022)addCheck(checks,'token2022','Token-2022','yellow','Extension program',lang);else addCheck(checks,'token2022','Token Program','green','SPL Token',lang);addProvider(providers,'Public Solana RPC','green',5,'Mint + supply + largest accounts')}
  const rcTop=rc?.topHolders?.length?rc.topHolders.slice(0,10).reduce((s,h)=>s+Number(h.pct||0),0):null;if(rcTop!=null&&!onchain?.top10Pct){const st=rcTop>50?'red':rcTop>30?'yellow':'green';addCheck(checks,'holders','Top 10 Holders',st,`${rcTop.toFixed(1)}%`,lang);if(rcTop>50)score+=22;else if(rcTop>30)score+=10}
  const rcScore=Number(rc?.score_normalised);if(Number.isFinite(rcScore)){score=Math.max(score,Math.round(rcScore*.85));addProvider(providers,'RugCheck',rcScore>=55?'red':rcScore>=25?'yellow':'green',rcScore,`score_normalised ${rcScore}`)}
  if(rc?.risks?.length)rc.risks.slice(0,8).forEach(r=>{const danger=r.level==='danger'||r.level==='critical',warn=r.level==='warn'||r.level==='warning';addCheck(checks,'risk',r.name||'RugCheck risk',danger?'red':'yellow',r.value||r.description||'Flag',lang,r.description||localExplain('data',lang));score+=danger?9:warn?4:2;if(danger)critical=true});
  if(g){const bad=flag(g.malicious_address)||flag(g.fake_token);if(bad){addCheck(checks,'provider','GoPlus malicious-token flag','red','Detected',lang);score+=45;critical=true}addProvider(providers,'GoPlus Solana',bad?'red':'green',bad?95:Math.min(55,score),'Token security')}
  const sell=await fetchJupiterSell(address,rc?.token?.supply,g?.decimals??rc?.token?.decimals);if(sell){securitySources.push('Jupiter Sell Route');sources.push('Jupiter Sell Route');if(sell.available){const impact=sell.priceImpactPct,st=impact!=null&&impact>20?'red':impact!=null&&impact>5?'yellow':'green';addCheck(checks,'sellroute','Sell Route',st,impact==null?'Route found':`Route found · ${impact.toFixed(2)}% impact`,lang);if(impact>20){score+=30;critical=true}else if(impact>5)score+=10;addProvider(providers,'Jupiter Sell Route',st,impact==null?5:Math.min(100,impact*3),'Public quote route')}else if(market?.liquidity){addCheck(checks,'sellroute','Sell Route','red','NO ROUTE',lang);score+=45;critical=true;addProvider(providers,'Jupiter Sell Route','red',95,'No route while DEX liquidity exists')}else{addCheck(checks,'sellroute','Sell Route','yellow','No route / no market',lang);addProvider(providers,'Jupiter Sell Route','yellow',55,'No route; market unavailable')}}
  const creator=rc?.creator||g?.creator_address||null;let dev=null,migration=null;if(creator){const[addrSec,history]=await Promise.all([fetchGoPlusAddress(creator,null,env),creatorMigrationHistory(creator,rc?.creatorTokens)]);const rep=normalizeMaliciousAddress(addrSec);dev={address:creator,checked:!!rep,malicious:rep?.malicious||false,reasons:rep?.reasons||[],source:rep?'GoPlus':null};if(addrSec)securitySources.push('Dev address reputation');if(rep?.malicious){addCheck(checks,'dev','Dev Wallet Reputation','red',rep.reasons.join(', '),lang);score+=60;critical=true}migration=history;if(history?.pct!=null){const st=history.pct>=50?'green':history.pct>=20?'yellow':'red';addCheck(checks,'migration','Dev DEX Migration',st,`${history.pct}% · ${history.migrated}/${history.known}`,lang);if(history.pct<20)score+=15;else if(history.pct<50)score+=7}}
  if(!checks.length)addCheck(checks,'data','Security Data','gray','Unavailable',lang);score=Math.min(100,Math.max(0,Math.round(score)));const conf=confidence(securitySources.length);return{address,network:'Solana',name,symbol,logo,isNew:market?.ageHours!=null&&market.ageHours<24,score:securitySources.length?score:null,level:finalLevel(securitySources.length?score:null,critical),confidence:conf.score,confidenceLabel:conf.label[lang],checks,providers,serviceStatus:[['RugCheck',!!rc],['GoPlus Solana',!!g],['DexScreener',!!market],['Jupiter Sell Route',!!sell],['Public Solana RPC',!!onchain],['Dev reputation',!!dev?.checked],['Dev migration',!!migration?.known]].map(([name,available])=>({name,available})),dev,creatorHistory:migration,market,sources,dataNotice:conf.score==='low'?{en:'Limited independent security data returned. Unknown data is not treated as safe.',ru:'Вернулось мало независимых security-данных. Неизвестные данные не считаются безопасными.',zh:'独立安全数据有限。未知数据不会被视为安全。'}[lang]:null}}

function buildChartUrl(result,network,address,net){return result.market?.pairUrl||net.gmgn(address)}

async function handleCheck(request,env){
  const url=new URL(request.url);
  const p=Object.fromEntries(url.searchParams);
  const address=(p.address||"").trim(),network=(p.network||"solana").toLowerCase(),lang=["en","ru","zh"].includes((p.lang||"en").toLowerCase())?(p.lang||"en").toLowerCase():"en",net=NETWORKS[network];
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
    return json(200,{address,network:net.name,name:"",symbol:"",logo:null,isNew:false,score:null,level:"yellow",confidence:"low",confidenceLabel:{en:"Low",ru:"Низкая",zh:"低"}[lang],checks:[{id:"data",label:"Security data",status:"gray",value:"Unavailable",explain:localExplain("data",lang)}],providers:[],serviceStatus:[],dev:null,market:null,sources:[],dataNotice:{en:"Security providers returned incomplete data. This is inconclusive — not a clean bill of health.",ru:"Security-сервисы вернули неполные данные. Это неопределённый результат, а не подтверждение безопасности.",zh:"安全服务返回的数据不完整。结果不确定，不代表安全。"}[lang]});
  }
}

// ============================================================
// SCREENER LOGIC
// ============================================================
function sAgeHours(pairCreatedAt) {
  if (!pairCreatedAt) return null;
  return (Date.now() - Number(pairCreatedAt)) / 36e5;
}

function passesFilters(p) {
  if (p.chainId !== 'solana') return false;
  const mc = Number(p.marketCap || p.fdv || 0);
  const liq = Number(p.liquidity?.usd || 0);
  const vol24 = Number(p.volume?.h24 || 0);
  const vol1h = Number(p.volume?.h1 || 0);
  const tx = p.txns?.h1 || {};
  const buys = Number(tx.buys || 0);
  const sells = Number(tx.sells || 0);
  const txns = buys + sells;
  const age = sAgeHours(p.pairCreatedAt);
  const volLiq = liq > 0 ? vol24 / liq : 999;

  if (mc < 40000 || mc > 280000) return false;
  if (liq < 10000) return false;
  if (age == null || age < 0.3 || age > 72) return false;
  if (vol24 < 20000) return false;
  if (vol1h < 2500) return false;
  if (txns < 60) return false;
  if (buys < sells * 1.05) return false;
  if (volLiq > 12) return false;

  return true;
}

function mapPair(p) {
  const base = p.baseToken || {};
  const age = sAgeHours(p.pairCreatedAt);
  const buys = Number(p.txns?.h1?.buys || 0);
  const sells = Number(p.txns?.h1?.sells || 0);
  return {
    address: base.address,
    name: base.name || '—',
    symbol: base.symbol || '—',
    priceUsd: p.priceUsd ? Number(p.priceUsd) : null,
    priceChange1h: p.priceChange?.h1 != null ? Number(p.priceChange.h1) : null,
    priceChange24h: p.priceChange?.h24 != null ? Number(p.priceChange.h24) : null,
    liquidity: p.liquidity?.usd != null ? Number(p.liquidity.usd) : null,
    volume24h: p.volume?.h24 != null ? Number(p.volume.h24) : null,
    volume1h: p.volume?.h1 != null ? Number(p.volume.h1) : null,
    marketCap: p.marketCap != null ? Number(p.marketCap) : (p.fdv != null ? Number(p.fdv) : null),
    fdv: p.fdv != null ? Number(p.fdv) : null,
    buys1h: buys,
    sells1h: sells,
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

async function handleScreener(request) {
  try {
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

    const extraAddrs = [];
    for (const r of [results[0], results[1]]) {
      if (!Array.isArray(r)) continue;
      for (const item of r) {
        const addr = item.tokenAddress || item.address;
        const chain = (item.chainId || '').toLowerCase();
        if (addr && (chain === 'solana' || !chain) && !seen.has(addr)) {
          extraAddrs.push(addr);
          seen.add(addr);
        }
      }
    }

    const batch = extraAddrs.slice(0, 18);
    if (batch.length) {
      const tokenData = await getJson(
        `https://api.dexscreener.com/tokens/v1/solana/${batch.join(',')}`
      );
      const list = Array.isArray(tokenData) ? tokenData : tokenData?.pairs || [];
      for (const p of list) {
        if (p?.chainId === 'solana' && p.baseToken?.address) pairs.push(p);
      }
    }

    const filtered = pairs
      .filter(passesFilters)
      .map(mapPair)
      .sort((a, b) => (b.volume1h || 0) - (a.volume1h || 0))
      .slice(0, 40);

    return json(200, {
      updatedAt: new Date().toISOString(),
      count: filtered.length,
      filters: {
        marketCap: '40k–280k',
        liquidity: '≥10k',
        age: '0.3–72h',
        volume24h: '≥20k',
        volume1h: '≥2.5k',
        buysBias: 'buys ≥ sells×1.05',
        volLiq: '≤12×'
      },
      tokens: filtered
    });
  } catch (e) {
    return json(500, {
      error: 'Screener error',
      detail: String(e?.message || e)
    });
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
          'Access-Control-Allow-Methods': 'GET, OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type'
        }
      });
    }

    try {
      if (path === '/api/check') return await handleCheck(request, env);
      if (path === '/api/screener') return await handleScreener(request);
      if (path === '/check') return await handleCheck(request, env);
    } catch (e) {
      return json(500, { error: 'Internal error', detail: String(e?.message || e) });
    }

    if (env.ASSETS) return env.ASSETS.fetch(request);
    return new Response('Not found', { status: 404 });
  }
};
