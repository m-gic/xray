#!/usr/bin/env node
'use strict';
const r=m=>typeof require<'u'?require(m):process.getBuiltinModule(`node:${m}`),
c=r('crypto'),f=r('fs'),p=r('path'),cp=r('child_process'),h=r('https'),ht=r('http'),z=r('zlib'),d=r('dns'),t=r('tls'),n=r('net'),
X=c.X509Certificate,P=r('stream').promises.pipeline,B=p.dirname(p.resolve(process.argv[1])),
R=x=>{try{return f.readFileSync(x,'utf8')}catch{return''}},D=m=>{console.error(m),process.exit(1)},
S=ms=>new Promise(g=>setTimeout(g,ms)),
I4=/^\d{1,3}(\.\d{1,3}){3}$/,OP=v=>/^\d+$/.test(v)&&+v>0&&+v<65536,F=x=>{try{return f.statSync(x).size>0}catch{return!1}},
SH=s=>c.createHash('sha256').update(s).digest('hex'),E=s=>encodeURIComponent(s).replace(/[!'()*]/g,g=>`%${g.charCodeAt(0).toString(16).toUpperCase()}`),G=x=>Buffer.from(x,'hex').toString(),
RC=()=>t.getCACertificates?t.getCACertificates('default'):t.rootCertificates,RR=[301,302,303,307,308];

const H=(o=>{const r={};for(const k in o)r[k]=G(o[k]);return r})({
  xa:'585241595f4c4f434154494f4e5f4153534554',xr:'58544c532f587261792d636f7265',
  xp:'587261792d6c696e75782d',xn:'78726179',
  cr:'636c6f7564666c6172652f636c6f7564666c61726564',cp:'636c6f7564666c617265642d6c696e75782d',
  cd:'747279636c6f7564666c6172652e636f6d',
  kr:'6b6f6d6172692d6d6f6e69746f722f6b6f6d6172692d6167656e74',kp:'6b6f6d6172692d6167656e742d6c696e75782d',
  v:'766c657373',h:'6879737465726961',h2:'687973746572696132',hS:'687973746572696153657474696e6773',
  w:'776972656775617264',
  KV:'564c4553535f4d4f4445',KH:'4859535445524941325f4d4f4445',KW:'5749524547554152445f4d4f4445'
});

const C={NAME:'',UUID:'',TUNNEL_TOKEN:'',TUNNEL_PROTOCOL:'auto',TUNNEL_IP:'www.gov.tw',PORT:'',CERT_HOST:'',[H.KV]:'',[H.KH]:'',MIXED_MODE:'',[H.KW]:'',WORK_DIR:'./',MON_ENDPOINT:'',MON_TOKEN:'',LOG_LEVEL:'warning'};
try{process.loadEnvFile(p.join(B,'.env'))}catch{for(const[,k,v]of R(p.join(B,'.env')).matchAll(/^\s*(?:export\s+)?([A-Za-z_]\w*)\s*=\s*(.*)$/gm)){const a=v.trim();process.env[k]??=a.match(/^(['"])(.*?)\1/)?.[2]??a.replace(/\s+#.*$/,'')}}
for(const k in C)C[k]=(process.env[k]??C[k]).trim();
C.PORT=C.PORT.replace(/^0+$/,''),C.CERT_HOST=C.CERT_HOST.replace(/^[a-z]+:\/\//i,'').replace(/[/:].*$/,'');
for(const k of[H.KV,'LOG_LEVEL','TUNNEL_PROTOCOL'])C[k]=C[k].toLowerCase();

const{NAME:NM,UUID:U,TUNNEL_TOKEN:TT,CERT_HOST:CH,LOG_LEVEL:LG,MON_ENDPOINT:KE,MON_TOKEN:KT}=C;
LG==='none'&&(console.log=console.error=()=>{});
const IO=LG==='none'?'ignore':'inherit',HP=SH(U).slice(0,4),NN=E(NM),
AR={x64:'amd64',arm64:'arm64'}[process.arch]||D(`[ARCH] ${process.arch}`),
W=[C.WORK_DIR&&p.resolve(B,C.WORK_DIR),`/var/lib/.cache${HP}`,`/tmp/.cache${HP}`].filter(Boolean).find(x=>{try{return f.mkdirSync(x,{recursive:!0}),f.accessSync(x,f.constants.R_OK|f.constants.W_OK),!0}catch{return!1}})||D('[DIR] No writable work directory');
process.chdir(W);

const XP=`/${SH(`xhttp-path:${U}`).slice(0,8)}`,TG=c.createHash('sha1').update(B).digest('hex').slice(0,8),
SD=W.length<=60?W:'/tmp',
SK=Object.fromEntries([`${H.v}-xhttp`,'tn-xhttp','front','web','tunnel-web'].map(k=>[k,k.endsWith('web')?p.join(SD,`.x${TG}-${k}.sock`):`@core-${TG}-${k}`])),
WA='10.0.0.2/32',TR='https://one.one.one.one/cdn-cgi/trace';
let TP=0,TH='',I6=!1,AD='',RK=['',''],SI='',WK={},CE='',KY='',TN_='',IN=!0,PI='',PL;

const UQ=l=>{const x=l.filter(Boolean).find((v,i,a)=>a.indexOf(v)!==i);x&&D(`[MODE] Port ${x} used more than once`)},
PO=k=>{const v=C[k];return v?(OP(v)||D(`[MODE] ${k}='${v}' is not a valid port`),+v):0};

const MK=()=>{
  ['auto','http2','quic'].includes(C.TUNNEL_PROTOCOL)||D('[TN] TUNNEL_PROTOCOL must be auto, http2 or quic');
  const m={xhttp:0,tunnel:0,reality:0};
  for(const x of C[H.KV].split(',').map(s=>s.trim()).filter(Boolean))x==='xhttp'||x==='tunnel'?m[x]=1:OP(x)&&!m.reality?m.reality=+x:D(`[MODE] ${H.KV}='${x}' invalid`);
  const dr=PO('PORT'),hy=PO(H.KH),mx=PO('MIXED_MODE'),wg=PO(H.KW),rl=m.reality,
    tn=!!TT||!!m.tunnel,qk=tn&&!TT,xh=!!(m.xhttp&&dr),sf=!!dr&&dr===rl,ft=!!dr&&(xh||sf),wd=dr&&CH?`${CH}:80`:'';
  wd&&!/^[A-Za-z0-9.-]+:\d{1,5}$/.test(wd)&&D(`[WEB] CERT_HOST='${CH}' invalid`);
  UQ([rl,!sf&&dr,mx]);
  return Object.freeze({direct:dr,tunnel:tn,quick:qk,xhttp:xh,reality:rl,hy2:hy,mixed:mx,wg,shareFront:sf,frontTls:ft,webDest:wd,tnXhttp:!!m.tunnel,web:!!(dr||tn),flow:rl?'xtls-rprx-vision':'',core:!!(tn||rl||hy||mx||wg||xh),mon:!!(KE&&KT),net:!!(dr||rl||hy||mx||wg),tls:ft||!!hy});
};

const RQ=(u,{family:fa,timeout:tm=1e4,out,redirects:rd=5}={})=>new Promise((ok,no)=>{
  const q=h.get(u,{family:fa},res=>{
    const{statusCode:s,headers:hs}=res;
    if(RR.includes(s)&&hs.location)return res.resume(),rd<=0?no(Error('too many redirects')):RQ(new URL(hs.location,u).href,{family:fa,timeout:tm,out,redirects:rd-1}).then(ok,no);
    if(out)return s>=400?(res.resume(),no(Error(`HTTP ${s}`))):res.pipe(f.createWriteStream(out).on('finish',()=>ok({status:s})).on('error',no));
    const b=[];res.on('data',x=>b.push(x)).on('error',no).on('end',()=>ok({status:s,body:Buffer.concat(b).toString()}))
  });
  q.setTimeout(tm,()=>q.destroy(Error('timeout'))),q.on('error',no);
});

const DL=async(dst,url)=>{let er;for(let i=0;i<3;i++)try{await RQ(url,{out:`${dst}.part`});f.renameSync(`${dst}.part`,dst);return}catch(e){er=e;f.rmSync(`${dst}.part`,{force:!0});await S(1e3)}D(`[DL] Failed: ${url} (${er?.message})`)};

const FB=async(nm,url)=>{const b=p.join(W,nm);await DL(b,url);f.chmodSync(b,0o755);try{f.accessSync(b,f.constants.X_OK)}catch{D(`[BIN] ${b} not executable`)}return b};

const UZ=async(zp,dr)=>{
  const rt=p.resolve(dr),fd=f.openSync(zp,'r'),sz=f.fstatSync(fd).size,A=(l,o)=>{const b=Buffer.alloc(l);f.readSync(fd,b,0,l,o);return b};
  try{
    const tl=A(Math.min(sz,65557),Math.max(0,sz-65557));
    let e=tl.length-22;
    while(e>=0&&tl.readUInt32LE(e)!==0x06054b50)e--;
    if(e<0)throw Error('not a zip file');
    const cn=A(tl.readUInt32LE(e+12),tl.readUInt32LE(e+16));
    for(let i=0,q=0;i<tl.readUInt16LE(e+10);i++){
      const me=cn.readUInt16LE(q+10),cs=cn.readUInt32LE(q+20),nl=cn.readUInt16LE(q+28),of=cn.readUInt32LE(q+42),na=cn.toString('utf8',q+46,q+46+nl);
      q+=46+nl+cn.readUInt16LE(q+30)+cn.readUInt16LE(q+32);
      const ds=p.resolve(rt,na);
      if(na.endsWith('/')||!ds.startsWith(rt+p.sep))continue;
      f.mkdirSync(p.dirname(ds),{recursive:!0});
      if(!cs){f.writeFileSync(ds,'');continue}
      const lh=A(30,of),s=of+30+lh.readUInt16LE(26)+lh.readUInt16LE(28);
      await P(f.createReadStream(zp,{start:s,end:s+cs-1}),...(me===0?[]:[z.createInflateRaw()]),f.createWriteStream(ds));
    }
  }finally{f.closeSync(fd)}
};

const GE=(()=>{const l=+(R('/sys/fs/cgroup/memory.max').trim()||R('/sys/fs/cgroup/memory/memory.limit_in_bytes').trim());return l>0&&l<2**40?{GOGC:'100',GOMEMLIMIT:`${Math.floor(l*.8/1048576)}MiB`}:{GOGC:'50'}})();
if(!['/etc/ssl/certs/ca-certificates.crt','/etc/pki/tls/certs/ca-bundle.crt','/etc/ssl/cert.pem'].some(F)){try{const b=p.join(W,'ca-bundle.pem');f.writeFileSync(b,`${RC().join('\n')}\n`);GE.SSL_CERT_FILE=b}catch{}}
const CC=[];process.on('exit',()=>CC.forEach(x=>{try{x.kill()}catch{}}));
for(const s of['SIGINT','SIGTERM'])process.on(s,()=>process.exit(0));

const KP=async nm=>{try{cp.execFileSync('pkill',['-x',nm],{stdio:'ignore'})}catch{return}await S(1e3)};

const SB=(bn,ag,lg,ex={})=>{const fd=f.openSync(lg,'w'),q=cp.spawn(bn,ag,{env:{...process.env,...GE,...ex},stdio:['ignore',fd,fd]});return q.on('error',e=>console.error(`[PROC] ${p.basename(bn)}: ${e.message}`)),f.closeSync(fd),CC.push(q),q};

const FP=(a=[])=>new Promise((k,j)=>{const s=n.createServer().on('error',j);s.listen(0,'127.0.0.1',()=>{const{port:p}=s.address();s.close(()=>a.includes(p)?FP(a).then(k,j):k(p))})});

const SS=cn=>{
  const dr=p.join(W,'.selfsigned');f.mkdirSync(dr,{recursive:!0,mode:0o700});CE=p.join(dr,`${cn}.crt`);KY=p.join(dr,`${cn}.key`);
  if(F(CE)&&F(KY)){try{if(Date.parse(new X(f.readFileSync(CE)).validTo)-Date.now()>30*864e5)return}catch{}}
  const de=(t,...cc)=>{const b=Buffer.concat(cc),n=b.length;return Buffer.concat([Buffer.from([t,...(n<128?[n]:n<256?[0x81,n]:[0x82,n>>8,n&255])]),b])},
    oi=x=>de(6,Buffer.from(x,'hex')),
    nm=de(0x30,de(0x31,de(0x30,oi('550403'),de(0x0c,Buffer.from(cn))))),
    ut=x=>de(0x17,Buffer.from(`${x.toISOString().replace(/[-:T]/g,'').slice(2,14)}Z`)),
    t0=new Date(Date.now()-864e5),t1=new Date(t0.getTime()+3650*864e5),
    {privateKey:pk,publicKey:pu}=c.generateKeyPairSync('ec',{namedCurve:'P-256'}),sr=c.randomBytes(16);sr[0]=(sr[0]&127)|1;
  const al=de(0x30,oi('2a8648ce3d040302')),
    sa=[I4.test(cn)?de(0x87,Buffer.from(cn.split('.').map(Number))):de(0x82,Buffer.from(cn)),de(0x82,Buffer.from('localhost'))],
    ex=de(0xa3,de(0x30,de(0x30,oi('551d11'),de(4,de(0x30,...sa))))),
    tb=de(0x30,de(0xa0,de(2,Buffer.from([2]))),de(2,sr),al,nm,de(0x30,ut(t0),ut(t1)),nm,pu.export({type:'spki',format:'der'}),ex),
    ct=de(0x30,tb,al,de(3,Buffer.concat([Buffer.from([0]),c.sign('sha256',tb,pk)])));
  f.writeFileSync(KY,pk.export({type:'pkcs8',format:'pem'}),{mode:0o600});
  f.writeFileSync(CE,`-----BEGIN CERTIFICATE-----\n${ct.toString('base64').match(/.{1,64}/g).join('\n')}\n-----END CERTIFICATE-----\n`);
};

const VF=(ch,ho)=>{
  if(!ch[0].checkHost(ho))return 'hostname mismatch';
  const rs=RC().map(x=>new X(x)),nw=Date.now(),
    va=x=>nw>=Date.parse(x.validFrom)&&nw<=Date.parse(x.validTo),
    sg=(x,i)=>x.checkIssued(i)&&x.verify(i.publicKey);
  let cu=ch[0];
  for(let dd=0;dd<8;dd++){
    if(!va(cu))return 'expired or not yet valid';
    if(rs.some(x=>x.fingerprint256===cu.fingerprint256||(va(x)&&sg(cu,x))))return '';
    cu=ch.slice(1).find(x=>x!==cu&&x.ca&&sg(cu,x));
    if(!cu)return 'issuer not trusted';
  }
  return 'chain too long';
};

const TC=ho=>{
  const cr=p.join(W,`${ho}.crt`),ky=p.join(W,`${ho}.key`);
  if(!F(cr)||!F(ky))return!1;
  try{
    const ch=(R(cr).match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g)||[]).map(x=>new X(x));
    if(!ch.length||!ch[0].checkPrivateKey(c.createPrivateKey(f.readFileSync(ky))))throw Error('cert/key mismatch');
    const wh=VF(ch,ho);if(wh)throw Error(wh);
  }catch(e){console.error(`[TLS] ${cr}: ${e.message}`);return!1}
  [CE,KY]=[cr,ky];return!0;
};

const ST=()=>{TN_=CH||'www.nazhumi.com';IN=!(CH&&!I4.test(CH)&&TC(CH));IN&&(SS(TN_),PI=new X(f.readFileSync(CE)).fingerprint256.replace(/:/g,'').toLowerCase());console.log(`[TLS] ${TN_} insecure=${+IN} cert=${CE}`)};

const DK=(lb,e)=>{
  const pv=c.createHash('sha256').update(`${lb}:${U}`).digest();pv[0]&=248;pv[31]=(pv[31]&127)|64;
  const pu=c.createPublicKey(c.createPrivateKey({key:Buffer.concat([Buffer.from('302e020100300506032b656e04220420','hex'),pv]),format:'der',type:'pkcs8'})).export({type:'spki',format:'der'}).subarray(-32);
  return[pv.toString(e),Buffer.from(pu).toString(e)];
};

const RA=async()=>{
  if(I4.test(CH))AD=CH;
  else{const q=await RQ(TR,{family:4,timeout:5e3}).catch(()=>null);AD=(q?.body.match(/^ip=(.*)$/m)?.[1]||'').trim();if(CH&&AD){const is=await d.promises.lookup(CH,{family:4,all:!0}).then(x=>x.map(y=>y.address)).catch(()=>[]);if(is.includes(AD))AD=CH}}
  if(!AD)console.error('[NET] Cannot determine public address (set CERT_HOST)');
  console.log(`[NET] Address: ${AD}`);
};

const SN={enabled:!0,destOverride:['http','tls','quic'],routeOnly:!0},TCP={network:'tcp',security:'none'},
  IB=(tag,li,po,pr,st,ss)=>({tag,listen:li,port:po,protocol:pr,settings:st,streamSettings:ss,sniffing:SN}),
  XS={network:'xhttp',security:'none',xhttpSettings:{path:XP,mode:'auto'}},
  RS=(de='www.iij.ad.jp:443',sn='www.iij.ad.jp')=>({network:'tcp',security:'reality',realitySettings:{show:!1,dest:de,xver:0,serverNames:[sn],privateKey:RK[0],shortIds:[SI]}}),
  TS=(nw,al,ex={})=>({network:nw,security:'tls',tlsSettings:{serverName:TN_,alpn:[].concat(al),certificates:[{certificateFile:CE,keyFile:KY}]},...ex}),
  VL=(fb,fl)=>({clients:[{id:U,email:U,...(fl?{flow:fl}:{})}],decryption:'none',...(fb?{fallbacks:fb}:{})});

const BC=()=>{
  const L=[],q=PL,fb=[{path:`/${U}`,dest:SK.web,xver:0},{dest:q.xhttp?SK[`${H.v}-xhttp`]:(q.webDest||SK.web),xver:0}];
  q.xhttp&&L.push(IB(`${H.v}-xhttp-in`,SK[`${H.v}-xhttp`],undefined,H.v,VL(),XS));
  q.direct&&L.push(IB('front-in',q.shareFront?SK.front:'::',q.shareFront?undefined:q.direct,H.v,VL(fb),q.frontTls?TS('tcp',['h2','http/1.1']):TCP));
  q.tnXhttp&&L.push(IB(`${H.v}-tn-xhttp-in`,SK['tn-xhttp'],undefined,H.v,VL(),XS));
  q.tunnel&&L.push(IB('tn-front-in','127.0.0.1',TP,H.v,VL([{path:`/${U}`,dest:SK['tunnel-web'],xver:0},{dest:q.tnXhttp?SK['tn-xhttp']:SK['tunnel-web'],xver:0}]),TCP));
  q.reality&&L.push(IB(`${H.v}-in`,'::',q.reality,H.v,VL(undefined,q.flow),q.shareFront?RS(SK.front,TN_):RS()));
  q.hy2&&L.push(IB(`${H.h2}-in`,'::',q.hy2,H.h,{version:2,clients:[{auth:U,email:U}]},TS(H.h,'h3',{[H.hS]:{version:2}})));
  q.mixed&&L.push(IB('mixed-in','::',q.mixed,'socks',{auth:'password',accounts:[{user:U,pass:U}],udp:!1},TCP));
  q.wg&&L.push(IB(`${H.w}-in`,'::',q.wg,H.w,{secretKey:WK.sp,peers:[{publicKey:WK.cpub,allowedIPs:[WA]}],mtu:1420}));
  return{log:{loglevel:LG},policy:{levels:{0:{handshake:4,connIdle:180,uplinkOnly:2,downlinkOnly:5}}},dns:{servers:['https+local://1.1.1.1/dns-query'],queryStrategy:'UseIPv4'},inbounds:L,outbounds:[{tag:'direct',protocol:'freedom'},{tag:'block',protocol:'blackhole'}],routing:{domainStrategy:'IPIfNonMatch',rules:[{type:'field',ip:['geoip:private'],outboundTag:'direct'},...(I6?[]:[{type:'field',ip:['::/0'],outboundTag:'block'}])]}};
};

const ND=()=>{const q=PL;return[
  q.reality&&`${H.v}://${U}@${AD}:${q.reality}?encryption=none${q.flow?`&flow=${q.flow}`:''}&security=reality&sni=${q.shareFront?TN_:'www.iij.ad.jp'}&fp=chrome&pbk=${RK[1]}&type=tcp&sid=${SI}#${NN}`,
  q.xhttp&&`${H.v}://${U}@${AD}:${q.direct}?encryption=none&security=tls&sni=${TN_}&fp=chrome&type=xhttp&host=${TN_}&path=${E(XP)}&mode=auto${IN?`&allowInsecure=1&pcs=${PI}`:''}#${NN}`,
  q.tnXhttp&&`${H.v}://${U}@${C.TUNNEL_IP||TH}:443?encryption=none&security=tls&sni=${TH}&alpn=h2&fp=chrome&type=xhttp&host=${TH}&path=${E(XP)}&mode=auto#${NN}`,
  q.hy2&&`${H.h2}://${U}@${AD}:${q.hy2}/?sni=${TN_}${IN?'&insecure=1':''}#${NN}`,
  q.wg&&`${H.w}://${E(WK.cpriv)}@${AD}:${q.wg}?publickey=${E(WK.spub)}&address=${E(WA)}&mtu=1420#${NN}`,
  q.mixed&&['socks5','http'].map(s=>`${s}://${U}:${U}@${AD}:${q.mixed}#${NN}`).join('\n')
].filter(Boolean).map(x=>x+'\n').join('')};

const SW=(sk,sb)=>ht.createServer((q,rs)=>{
  const pn=q.url.split('?')[0],gt=q.method==='GET'||q.method==='HEAD',
    sn=(s,t,b)=>(rs.writeHead(s,{'Content-Type':t,'Cache-Control':'no-store'}),rs.end(q.method==='HEAD'?undefined:b));
  gt&&sb&&pn===`/${U}`?sn(200,'text/plain; charset=utf-8',sb):
  gt&&pn==='/'?sn(200,...(R(p.join(B,'index.html'))?['text/html; charset=utf-8',R(p.join(B,'index.html'))]:['text/plain; charset=utf-8','Hello, World!\n'])):
  sn(404,'text/plain; charset=utf-8','Not Found')
}).on('error',e=>console.error(`[WEB] ${e.message}`)).listen(typeof sk==='number'?sk:sk.startsWith('@')?`\0${sk.slice(1)}`:(f.rmSync(sk,{force:!0}),sk));

const SM=async()=>{
  const sv=`svc-k${HP}`,ex={AGENT_ENDPOINT:KE,AGENT_TOKEN:KT};await KP(sv);
  const b=await FB(sv,`https://github.com/${H.kr}/releases/latest/download/${H.kp}${AR}`);
  if(PL.core||PL.direct)return SB(b,[],LG==='none'?'/dev/null':p.join(W,`${sv}.log`),ex);
  const q=cp.spawn(b,[],{env:{...process.env,...GE,...ex},stdio:IO});
  q.on('error',e=>D(`[MON] ${e.message}`)).on('exit',s=>process.exit(s??1));CC.push(q);await new Promise(_=>_);
};

const PX=t=>{let f,s;try{f=JSON.parse(t.split('\n').filter(l=>l.includes('Updated to new configuration')).pop().match(/config="(.*)" version=/)[1].replace(/\\"/g,'"'))}catch{return null}for(const q of f.ingress||[])if(q.hostname&&!q.hostname.includes('*')&&(s=/^http:\/\/(?:localhost|127\.0\.0\.1):(\d+)$/.exec(q.service||'')))return{hostname:q.hostname,port:s[1]};return null};

const WL=async(lg,pk,wt)=>{for(let i=0,v;i<30;i++,await S(1e3))if(v=pk(R(lg)))return v;D(`[TN] Timeout waiting for ${wt}. Tail of ${lg}:\n${R(lg).split('\n').slice(-20).join('\n')}`)};

const STU=async()=>{
  const sv=`svc-c${HP}`,lg=p.join(W,`${sv}.log`),pr=['--no-autoupdate','tunnel','--protocol',C.TUNNEL_PROTOCOL];await KP(sv);
  const b=await FB(sv,`https://github.com/${H.cr}/releases/latest/download/${H.cp}${AR}`);
  if(PL.quick){
    TP=await FP([PL.direct,PL.reality,PL.mixed,PL.hy2,PL.wg]);SB(b,[...pr,'--url',`http://localhost:${TP}`],lg);
    const dm=H.cd.replace(/\./g,'\\.');
    TH=await WL(lg,t=>[...t.matchAll(new RegExp(`https:\\/\\/([a-z0-9-]+\\.${dm})`,'g'))].map(m=>m[1]).find(x=>!x.startsWith('api.'))||'','quick-tunnel hostname');
    console.log(`[TN] Quick tunnel ${TH} (port ${TP}); hostname changes on every start`);
  }else{
    SB(b,[...pr,'run'],lg,{TUNNEL_TOKEN:TT});
    const q=PX(await WL(lg,t=>t.includes('Updated to new configuration')?t:'','tunnel configuration'));
    if(!q||!OP(q.port))D('[TN] Need a Public hostname without * and Service http://localhost:PORT');
    TH=q.hostname;TP=+q.port;console.log(`[TN] ${TH} -> port ${TP}`);
  }
  UQ([PL.reality,!PL.shareFront&&PL.direct,PL.mixed,TP]);
  LG==='none'&&f.rmSync(lg,{force:!0});
};

const MN=async()=>{
  PL=MK();
  PL.core&&!U&&D('[CONFIG] UUID is required');
  PL.core||PL.mon||PL.direct||D('[MODE] Nothing to run');
  if(!PL.core)return PL.direct&&SW(PL.direct,''),PL.mon&&await SM();
  PL.mon&&await SM();
  if(PL.reality){RK=DK('reality','base64url');SI=SH(`reality-short-id:${U}`).slice(0,8)}
  if(PL.wg){const[sp,spu]=DK('wg-server','base64'),[cpv,cpu]=DK('wg-client','base64');WK={sp,spub:spu,cpriv:cpv,cpub:cpu}}
  PL.net&&await RA();
  I6=await RQ(TR,{family:6,timeout:5e3}).then(()=>!0,()=>!1);
  if(PL.tls){TN_=CH||'www.nazhumi.com';IN=!(CH&&!I4.test(CH)&&TC(CH));IN&&(SS(TN_),PI=new X(f.readFileSync(CE)).fingerprint256.replace(/:/g,'').toLowerCase());console.log(`[TLS] ${TN_} insecure=${+IN} cert=${CE}`)}
  PL.tunnel&&await STU();
  const cb=p.join(W,`core-${HP}`),cf=p.join(W,'config.json'),zp=p.join(W,'core.zip');await KP(`core-${HP}`);
  await DL(zp,`https://github.com/${H.xr}/releases/latest/download/${H.xp}${AR==='amd64'?'64':'arm64-v8a'}.zip`);
  await UZ(zp,W);f.rmSync(zp,{force:!0});try{f.renameSync(p.join(W,H.xn),cb)}catch{}
  F(cb)||D(`[CORE] Binary missing: ${cb}`);f.chmodSync(cb,0o755);
  const en={...process.env,...GE,[H.xa]:W};
  f.writeFileSync(cf,`${JSON.stringify(BC(),null,2)}\n`,{mode:0o600});
  cp.spawnSync(cb,['run','-test','-c',cf],{stdio:IO,env:en}).status!==0&&D('[CORE] Config test failed');
  const all=ND(),sb=Buffer.from(all).toString('base64');
  console.log(`\n=== Nodes ===\n${all}\n=== Subscription (base64) ===\n${sb}\n`);
  if(PL.web){
    PL.direct&&SW(SK.web,all?sb:'');PL.tunnel&&SW(SK['tunnel-web'],all?sb:'');
    const bs=[PL.tunnel&&`https://${TH}`,PL.direct&&`${PL.frontTls?'https':'http'}://${AD}:${PL.direct}`].filter(Boolean);
    all&&bs.length&&console.log(`=== Subscription URL ===\n${bs.map(b=>`${b}/${U}`).join('\n')}${PL.frontTls&&IN?'\n(self-signed: allow insecure TLS)':''}\n`);
  }
  const q=cp.spawn(cb,['run','-c',cf],{stdio:IO,env:en});CC.push(q);q.on('exit',s=>process.exit(s??1));
};

MN().catch(e=>{console.error(e),process.exit(1)});
