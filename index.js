#!/usr/bin/env node
'use strict';
const req = typeof require === 'function' ? require : (m) => process.getBuiltinModule(`node:${m}`);
const crypto = req('crypto'), fs = req('fs'), path = req('path'), cp = req('child_process');
const [https, http, zlib, dns, tls, net] = ['https', 'http', 'zlib', 'dns', 'tls', 'net'].map((m) => req(m));
const { X509Certificate } = crypto, { pipeline } = req('stream').promises;
const BASE_DIR = path.dirname(path.resolve(process.argv[1]));

const readText = (f) => { try { return fs.readFileSync(f, 'utf8'); } catch { return ''; } };
const nonEmpty = (f) => { try { return fs.statSync(f).size > 0; } catch { return false; } };
const die = (msg) => { console.error(msg); process.exit(1); };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const IPV4 = /^\d{1,3}(\.\d{1,3}){3}$/;
const validPort = (v) => /^\d+$/.test(v) && +v >= 1 && +v <= 65535;
const sha256 = (s) => crypto.createHash('sha256').update(s).digest('hex');
const urlEncode = (t) => encodeURIComponent(t).replace(/[!'()*]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`);
const abs = (s) => `\0${s.slice(1)}`; // Xray 的 "@name" 抽象套接字 -> Node 的 "\0name"

// ========== 用户配置(优先级：环境变量 > 同目录 .env > 默认值) ==========
const CONFIG = {
  NAME: '',
  UUID: '',
  CLOUDFLARE_TUNNEL_TOKEN: '',
  CLOUDFLARE_PROTOCOL: 'auto',
  PORT: '',
  CERT_HOST: '',
  VLESS_MODE: '',
  HYSTERIA2_MODE: '',
  MIXED_MODE: '',
  WIREGUARD_MODE: '',
  WORK_DIR: './',
  KOMARI_ENDPOINT: '',
  KOMARI_TOKEN: '',
  LOG_LEVEL: 'warning',
};

try { process.loadEnvFile(path.join(BASE_DIR, '.env')); } catch {
  for (const [, k, v] of readText(path.join(BASE_DIR, '.env')).matchAll(/^\s*(?:export\s+)?([A-Za-z_]\w*)\s*=\s*(.*)$/gm)) {
    const raw = v.trim();
    process.env[k] ??= raw.match(/^(['"])(.*?)\1/)?.[2] ?? raw.replace(/\s+#.*$/, '');
  }
}
for (const k of Object.keys(CONFIG)) CONFIG[k] = (process.env[k] ?? CONFIG[k]).trim();
CONFIG.PORT = CONFIG.PORT.replace(/^0+$/, '');
CONFIG.CERT_HOST = CONFIG.CERT_HOST.replace(/^[a-z]+:\/\//i, '').replace(/[/:].*$/, '');
CONFIG.VLESS_MODE = CONFIG.VLESS_MODE.toLowerCase();
CONFIG.LOG_LEVEL = CONFIG.LOG_LEVEL.toLowerCase();
CONFIG.CLOUDFLARE_PROTOCOL = CONFIG.CLOUDFLARE_PROTOCOL.toLowerCase();
for (const k of ['VMESS_MODE', 'TROJAN_MODE', 'SHADOWSOCKS_MODE']) if (process.env[k]) console.error(`[MODE] ${k} is no longer supported and is ignored`);

const { NAME, UUID, CLOUDFLARE_TUNNEL_TOKEN: TUNNEL, PORT, CERT_HOST, LOG_LEVEL: LOG, KOMARI_ENDPOINT: KOMARI_EP, KOMARI_TOKEN } = CONFIG;
if (LOG === 'none') console.log = console.error = () => {};
const STDIO = LOG === 'none' ? 'ignore' : 'inherit';
const uuidHash = sha256(UUID), hp = uuidHash.slice(0, 4), N = urlEncode(NAME);
const ARCH = { x64: 'amd64', arm64: 'arm64' }[process.arch] || die(`[ARCH] Unsupported architecture: ${process.arch}`);
console.log('[ENV]', Object.entries(CONFIG).filter(([, v]) => v)
  .map(([k, v]) => `${k}=${/UUID|TOKEN/.test(k) ? `${v.slice(0, 4)}***` : v}`).join(' '));

const WORK = [CONFIG.WORK_DIR && path.resolve(BASE_DIR, CONFIG.WORK_DIR), `/var/lib/.cache${hp}`, `/tmp/.cache${hp}`]
  .filter(Boolean).find((d) => {
    try { fs.mkdirSync(d, { recursive: true }); fs.accessSync(d, fs.constants.R_OK | fs.constants.W_OK); return true; }
    catch (e) { console.error(`[DIR] Cannot access ${d}: ${e.message}`); return false; }
  }) || process.exit(1);
console.log(`[DIR] Work directory: ${WORK}`);
process.chdir(WORK);

// ========== 协议常量 ==========
const XHTTP_PATH = `/${sha256(`xhttp-path:${UUID}`).slice(0, 8)}`;
const sha1Tag = crypto.createHash('sha1').update(BASE_DIR).digest('hex').slice(0, 8);
const SOCK = Object.fromEntries(['vless-xhttp', 'cf-xhttp', 'front', 'web', 'tunnel-web'].map((n) => [n, `@xray-${sha1Tag}-${n}`]));
const WG_CLIENT_ADDR = '10.0.0.2/32', TRACE = 'https://one.one.one.one/cdn-cgi/trace';

// ========== 运行状态 ==========
let CF_PORT = 0, CF_HOST = '', IPV6 = false, PUBLIC_ADDR = '';
let RK_PRIV = '', RK_PUB = '', SID = '', WGK = {};
let CERT_FILE = '', KEY_FILE = '', TLS_NAME = '', TLS_INSECURE = true, PIN = '';
let plan;

const uniquePorts = (list) => {
  const ports = list.filter(Boolean);
  const dup = ports.find((p, i) => ports.indexOf(p) !== i);
  if (dup !== undefined) die(`[MODE] Port ${dup} is used more than once`);
};

// ========== 运行计划：所有联动规则集中于此 ==========
function makePlan() {
  if (TUNNEL === 'try') die("[CF] CLOUDFLARE_TUNNEL_TOKEN='try' is no longer supported. Leave it empty and set VLESS_MODE to include cloudflare to use a quick tunnel");
  if (!['auto', 'http2', 'quic'].includes(CONFIG.CLOUDFLARE_PROTOCOL)) die(`[CF] CLOUDFLARE_PROTOCOL='${CONFIG.CLOUDFLARE_PROTOCOL}' is invalid (expected auto, http2 or quic)`);

  const mode = { xhttp: false, cloudflare: false, reality: 0 };
  for (const t of CONFIG.VLESS_MODE.split(',').map((s) => s.trim()).filter(Boolean)) {
    if (t === 'ws') die("[MODE] VLESS_MODE: 'ws' is no longer supported, use xhttp");
    if (t === 'xhttp' || t === 'cloudflare') {
      if (mode[t]) die(`[MODE] VLESS_MODE: '${t}' is given more than once`);
      mode[t] = true;
    } else if (/^\d+$/.test(t)) {
      if (!validPort(t)) die(`[MODE] VLESS_MODE='${t}': port must be 1-65535`);
      if (mode.reality) die('[MODE] VLESS_MODE: only one Reality port is allowed');
      mode.reality = +t;
    } else die(`[MODE] VLESS_MODE='${t}' is invalid (expected xhttp, cloudflare or a port)`);
  }

  const port = (name, v, desc) => {
    if (!v) return 0;
    if (!validPort(v)) die(`[MODE] ${name}='${v}' is invalid (expected a port 1-65535, or empty to disable)`);
    console.log(`[MODE] port ${+v}/${desc}`);
    return +v;
  };
  const direct = port('PORT', PORT, 'web');
  const hy2 = port('HYSTERIA2_MODE', CONFIG.HYSTERIA2_MODE, 'udp: hysteria2');
  const mixed = port('MIXED_MODE', CONFIG.MIXED_MODE, 'tcp: mixed (socks5 + http)');
  const wg = port('WIREGUARD_MODE', CONFIG.WIREGUARD_MODE, 'udp: wireguard');
  const reality = mode.reality;

  const quick = mode.cloudflare && !TUNNEL, tunnel = !!TUNNEL || quick;
  if (quick) console.log('[MODE] CLOUDFLARE_TUNNEL_TOKEN is empty: cloudflare mode uses a quick tunnel');

  const xhttp = mode.xhttp && !!direct;
  if (mode.xhttp && !direct) console.log('[MODE] PORT is empty: xhttp is disabled (xhttp needs a direct PORT)');
  const shareFront = !!direct && direct === reality;
  const frontTls = !!direct && (xhttp || shareFront);
  const webDest = direct && CERT_HOST ? `${CERT_HOST}:80` : '';
  if (webDest && !/^[A-Za-z0-9.-]+:\d{1,5}$/.test(webDest)) die(`[WEB] CERT_HOST='${CERT_HOST}' is invalid (expected a domain or an IPv4 address)`);
  if (webDest) console.log(`[WEB] Fallback for other paths on the front port: ${webDest}`);

  uniquePorts([reality, !shareFront && direct, mixed]);

  const proxy = !!(tunnel || reality || hy2 || mixed || wg || xhttp); // 只有代理协议需要 Xray
  const anyNet = !!(direct || reality || hy2 || mixed || wg);
  return Object.freeze({
    direct, tunnel, quick, xhttp, reality, hy2, mixed, wg, shareFront, frontTls, webDest,
    cfXhttp: mode.cloudflare && tunnel,
    web: !!(direct || tunnel),
    flow: reality ? 'xtls-rprx-vision' : '',
    xray: proxy,
    komari: !!(KOMARI_EP && KOMARI_TOKEN),
    net: anyNet,
    tls: frontTls || !!hy2,
  });
}

// ========== 网络 / 文件 ==========
// HTTPS 请求：跟随重定向；传 outputFile 则写入文件，否则返回 { status, body }
function request(url, { family, timeout = 10000, outputFile, redirects = 5 } = {}) {
  return new Promise((resolve, reject) => {
    const r = https.get(url, { family }, (res) => {
      const { statusCode: code, headers } = res;
      if ([301, 302, 303, 307, 308].includes(code) && headers.location) {
        res.resume();
        return redirects <= 0 ? reject(new Error('too many redirects'))
          : request(new URL(headers.location, url).href, { family, timeout, outputFile, redirects: redirects - 1 }).then(resolve, reject);
      }
      if (outputFile) {
        if (code >= 400) { res.resume(); return reject(new Error(`HTTP ${code}`)); }
        return res.pipe(fs.createWriteStream(outputFile).on('finish', () => resolve({ status: code })).on('error', reject));
      }
      const chunks = [];
      res.on('data', (c) => chunks.push(c))
        .on('end', () => resolve({ status: code, body: Buffer.concat(chunks).toString() }))
        .on('error', reject);
    });
    r.setTimeout(timeout, () => r.destroy(new Error('timeout')));
    r.on('error', reject);
  });
}

// 先写 .part 再改名，失败重试 3 次
async function download(dest, url) {
  let err;
  for (let i = 0; i < 3; i++) {
    try { await request(url, { outputFile: `${dest}.part` }); fs.renameSync(`${dest}.part`, dest); return true; }
    catch (e) { err = e; fs.rmSync(`${dest}.part`, { force: true }); await sleep(1000); }
  }
  console.error(`[DL] Download failed: ${url} (${err?.code ?? ''} ${err?.message ?? 'unknown error'})`);
  return false;
}

async function fetchBin(name, url) {
  const bin = path.join(WORK, name);
  if (!await download(bin, url)) process.exit(1);
  fs.chmodSync(bin, 0o755);
  return bin;
}

// 流式解压 zip：只读中央目录，逐文件解压
async function unzip(zipPath, dir) {
  const root = path.resolve(dir), fd = fs.openSync(zipPath, 'r'), size = fs.fstatSync(fd).size;
  const readAt = (len, pos) => { const b = Buffer.alloc(len); fs.readSync(fd, b, 0, len, pos); return b; };
  try {
    const tail = readAt(Math.min(size, 65557), Math.max(0, size - 65557));
    let eocd = tail.length - 22;
    while (eocd >= 0 && tail.readUInt32LE(eocd) !== 0x06054b50) eocd--;
    if (eocd < 0) throw new Error('not a zip file');
    const central = readAt(tail.readUInt32LE(eocd + 12), tail.readUInt32LE(eocd + 16));
    for (let i = 0, cur = 0; i < tail.readUInt16LE(eocd + 10); i++) {
      const method = central.readUInt16LE(cur + 10), csize = central.readUInt32LE(cur + 20);
      const nlen = central.readUInt16LE(cur + 28), offset = central.readUInt32LE(cur + 42);
      const name = central.toString('utf8', cur + 46, cur + 46 + nlen);
      cur += 46 + nlen + central.readUInt16LE(cur + 30) + central.readUInt16LE(cur + 32);
      const dest = path.resolve(root, name);
      if (name.endsWith('/') || !dest.startsWith(root + path.sep)) continue;
      fs.mkdirSync(path.dirname(dest), { recursive: true });
      if (!csize) { fs.writeFileSync(dest, ''); continue; }
      const lh = readAt(30, offset), start = offset + 30 + lh.readUInt16LE(26) + lh.readUInt16LE(28);
      await pipeline(fs.createReadStream(zipPath, { start, end: start + csize - 1 }),
        ...(method === 0 ? [] : [zlib.createInflateRaw()]), fs.createWriteStream(dest));
    }
  } finally { fs.closeSync(fd); }
}

// Go 程序内存参数：有容器内存限制时交给 GOMEMLIMIT，否则 GOGC=50 省内存
const GO_ENV = (() => {
  const limit = +(readText('/sys/fs/cgroup/memory.max').trim() || readText('/sys/fs/cgroup/memory/memory.limit_in_bytes').trim());
  return limit > 0 && limit < 2 ** 40
    ? { GOGC: 'off', GOMEMLIMIT: `${Math.floor(limit * 0.6 / 1048576)}MiB` }
    : { GOGC: '50' };
})();

const children = [];
process.on('exit', () => children.forEach((c) => { try { c.kill(); } catch {} }));
for (const sig of ['SIGINT', 'SIGTERM']) process.on(sig, () => process.exit(0));

async function killPrevious(name, tag) {
  try { cp.execFileSync('pkill', ['-x', name], { stdio: 'ignore' }); } catch { return; }
  console.log(`[${tag}] Stopped previous ${name}`);
  await sleep(1000);
}

function spawnBg(bin, args, logFile, extra = {}) {
  const fd = fs.openSync(logFile, 'w');
  const child = cp.spawn(bin, args, { env: { ...process.env, ...GO_ENV, ...extra }, stdio: ['ignore', fd, fd] });
  fs.closeSync(fd);
  children.push(child);
  return child;
}

// 取一个本机空闲 TCP 端口，避开 avoid 中的端口
const freePort = (avoid = []) => new Promise((resolve, reject) => {
  const s = net.createServer().on('error', reject);
  s.listen(0, '127.0.0.1', () => {
    const { port } = s.address();
    s.close(() => (avoid.includes(port) ? freePort(avoid).then(resolve, reject) : resolve(port)));
  });
});

// ========== TLS 证书 ==========
// 自签证书(RSA 2048，10 年)；已有且 30 天内不过期则复用
function selfSigned(cn) {
  const dir = path.join(WORK, '.selfsigned');
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  CERT_FILE = path.join(dir, `${cn}.crt`);
  KEY_FILE = path.join(dir, `${cn}.key`);
  if (nonEmpty(CERT_FILE) && nonEmpty(KEY_FILE)) {
    try { if (Date.parse(new X509Certificate(fs.readFileSync(CERT_FILE)).validTo) - Date.now() > 30 * 86400e3) return; } catch {}
  }
  cp.execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '3650',
    '-keyout', KEY_FILE, '-out', CERT_FILE, '-subj', `/CN=${cn}`, '-addext', `subjectAltName=DNS:${cn},DNS:localhost`], { stdio: 'ignore' });
  fs.chmodSync(KEY_FILE, 0o600);
}

// 校验证书链：域名匹配、逐级验签、落在系统信任根上；返回空串表示可信
function verifyChain(chain, host) {
  if (!chain[0].checkHost(host)) return 'hostname mismatch';
  const roots = (tls.getCACertificates ? tls.getCACertificates('default') : tls.rootCertificates).map((p) => new X509Certificate(p));
  const now = Date.now(), valid = (c) => now >= Date.parse(c.validFrom) && now <= Date.parse(c.validTo);
  const signedBy = (c, i) => c.checkIssued(i) && c.verify(i.publicKey);
  let cur = chain[0];
  for (let d = 0; d < 8; d++) {
    if (!valid(cur)) return 'certificate expired or not yet valid';
    if (roots.some((r) => r.fingerprint256 === cur.fingerprint256 || (valid(r) && signedBy(cur, r)))) return '';
    cur = chain.slice(1).find((i) => i !== cur && i.ca && signedBy(cur, i));
    if (!cur) return 'issuer is not trusted';
  }
  return 'chain too long';
}

function trustedCert(host) {
  const crt = path.join(WORK, `${host}.crt`), key = path.join(WORK, `${host}.key`);
  if (!nonEmpty(crt) || !nonEmpty(key)) return false;
  let chain;
  try {
    chain = (fs.readFileSync(crt, 'utf8').match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g) || [])
      .map((p) => new X509Certificate(p));
    if (!chain.length || !chain[0].checkPrivateKey(crypto.createPrivateKey(fs.readFileSync(key)))) throw new Error('no matching certificate and key');
  } catch (e) { console.error(`[TLS] Cannot read ${crt} / ${key}: ${e.message}`); return false; }
  const reason = verifyChain(chain, host);
  if (reason) { console.error(`[TLS] ${crt} is not trusted for ${host}: ${reason}`); return false; }
  CERT_FILE = crt;
  KEY_FILE = key;
  return true;
}

function setupTls() {
  TLS_NAME = CERT_HOST || 'www.nazhumi.com';
  TLS_INSECURE = !(CERT_HOST && !IPV4.test(CERT_HOST) && trustedCert(CERT_HOST));
  if (TLS_INSECURE) {
    console.error(`[TLS] No trusted certificate (put one at ${WORK}/<CERT_HOST>.crt and .key), using self-signed certificate`);
    selfSigned(TLS_NAME);
    PIN = new X509Certificate(fs.readFileSync(CERT_FILE)).fingerprint256.replace(/:/g, '').toLowerCase();
  }
  console.log(`[TLS] Server name: ${TLS_NAME}, insecure: ${TLS_INSECURE ? 1 : 0}, cert: ${CERT_FILE}`);
}

// ========== 密钥(由 UUID 派生，同一 UUID 永远得到同一组密钥) ==========
function deriveKey(label, enc) {
  const priv = crypto.createHash('sha256').update(`${label}:${UUID}`).digest();
  priv[0] &= 248;
  priv[31] = (priv[31] & 127) | 64;
  const pub = crypto.createPublicKey(crypto.createPrivateKey({
    key: Buffer.concat([Buffer.from('302e020100300506032b656e04220420', 'hex'), priv]), format: 'der', type: 'pkcs8',
  })).export({ type: 'spki', format: 'der' }).subarray(-32);
  return [priv.toString(enc), Buffer.from(pub).toString(enc)];
}

// 公网地址：CERT_HOST 是 IP 直接用；是域名且指向本机时用域名；否则用探测到的出口 IP
async function resolveAddr() {
  if (IPV4.test(CERT_HOST)) PUBLIC_ADDR = CERT_HOST;
  else {
    const t = await request(TRACE, { family: 4, timeout: 5000 }).catch(() => null);
    PUBLIC_ADDR = ((t && t.body.match(/^ip=(.*)$/m)) || [, ''])[1].trim();
    if (CERT_HOST && PUBLIC_ADDR) {
      const ips = await dns.promises.lookup(CERT_HOST, { family: 4, all: true }).then((es) => es.map((e) => e.address)).catch(() => []);
      if (ips.includes(PUBLIC_ADDR)) {
        console.log(`[NET] ${CERT_HOST} points to this server, using it instead of the IP`);
        PUBLIC_ADDR = CERT_HOST;
      }
    }
  }
  if (!PUBLIC_ADDR) console.error('[NET] Cannot determine the public address, links will be invalid (set CERT_HOST)');
  console.log(`[NET] Address in links: ${PUBLIC_ADDR}`);
}

// ========== Xray 配置 ==========
const SNIFF = { enabled: true, destOverride: ['http', 'tls', 'quic'], routeOnly: true };
const TCP = { network: 'tcp', security: 'none' };
const ib = (tag, listen, port, protocol, settings, streamSettings) => ({ tag, listen, port, protocol, settings, streamSettings, sniffing: SNIFF });
const xhttpStream = (p) => ({ network: 'xhttp', security: 'none', xhttpSettings: { path: p, mode: 'auto' } });
const realityStream = (dest = 'www.iij.ad.jp:443', sn = 'www.iij.ad.jp') => ({
  network: 'tcp', security: 'reality',
  realitySettings: { show: false, dest, xver: 0, serverNames: [sn], privateKey: RK_PRIV, shortIds: [SID] },
});
const tlsStream = (network, alpn, extra = {}) => ({
  network, security: 'tls',
  tlsSettings: { serverName: TLS_NAME, alpn: [].concat(alpn), certificates: [{ certificateFile: CERT_FILE, keyFile: KEY_FILE }] },
  ...extra,
});
const vlessSettings = (fallbacks, flow) => ({
  clients: [{ id: UUID, email: UUID, ...(flow ? { flow } : {}) }], decryption: 'none', ...(fallbacks ? { fallbacks } : {}),
});

function buildConfig() {
  const inbounds = [];
  // xhttp 走默认回落：Xray 的 fallback path 不支持 h2，xhttp 放在无 path 条件的最后一条
  const fallbacks = [
    { path: `/${UUID}`, dest: SOCK.web, xver: 0 },
    { dest: plan.xhttp ? SOCK['vless-xhttp'] : (plan.webDest || SOCK.web), xver: 0 },
  ];
  if (plan.xhttp) inbounds.push(ib('vless-xhttp-in', SOCK['vless-xhttp'], undefined, 'vless', vlessSettings(), xhttpStream(XHTTP_PATH)));
  if (plan.direct) inbounds.push(ib('front-in', plan.shareFront ? SOCK.front : '::', plan.shareFront ? undefined : plan.direct, 'vless',
    vlessSettings(fallbacks), plan.frontTls ? tlsStream('tcp', ['h2', 'http/1.1']) : TCP));
  if (plan.cfXhttp) inbounds.push(ib('vless-cf-xhttp-in', SOCK['cf-xhttp'], undefined, 'vless', vlessSettings(), xhttpStream(XHTTP_PATH)));
  // 隧道入口只供本机 cloudflared 访问，仅监听回环地址
  if (plan.tunnel) inbounds.push(ib('cf-front-in', '127.0.0.1', CF_PORT, 'vless',
    vlessSettings([
      { path: `/${UUID}`, dest: SOCK['tunnel-web'], xver: 0 },
      { dest: plan.cfXhttp ? SOCK['cf-xhttp'] : SOCK['tunnel-web'], xver: 0 },
    ]), TCP));
  if (plan.reality) inbounds.push(ib('vless-in', '::', plan.reality, 'vless', vlessSettings(undefined, plan.flow),
    plan.shareFront ? realityStream(SOCK.front, TLS_NAME) : realityStream()));
  if (plan.hy2) inbounds.push(ib('hysteria2-in', '::', plan.hy2, 'hysteria',
    { version: 2, clients: [{ auth: UUID, email: UUID }] }, tlsStream('hysteria', 'h3', { hysteriaSettings: { version: 2 } })));
  if (plan.mixed) inbounds.push(ib('mixed-in', '::', plan.mixed, 'socks',
    { auth: 'password', accounts: [{ user: UUID, pass: UUID }], udp: false }, TCP));
  if (plan.wg) inbounds.push(ib('wireguard-in', '::', plan.wg, 'wireguard',
    { secretKey: WGK.sp, peers: [{ publicKey: WGK.cpub, allowedIPs: [WG_CLIENT_ADDR] }], mtu: 1420 }));

  return {
    log: { loglevel: LOG },
    policy: { levels: { 0: { handshake: 4, connIdle: 180, uplinkOnly: 2, downlinkOnly: 5 } } },
    dns: { servers: ['https+local://1.1.1.1/dns-query'], queryStrategy: 'UseIPv4' },
    inbounds,
    outbounds: [{ tag: 'direct', protocol: 'freedom' }, { tag: 'block', protocol: 'blackhole' }],
    routing: {
      domainStrategy: 'IPIfNonMatch',
      rules: [
        { type: 'field', ip: ['geoip:private'], outboundTag: 'direct' },
        ...(IPV6 ? [] : [{ type: 'field', ip: ['::/0'], outboundTag: 'block' }]),
      ],
    },
  };
}

// ========== 订阅链接 ==========
const realityLink = () => `vless://${UUID}@${PUBLIC_ADDR}:${plan.reality}?encryption=none${plan.flow ? `&flow=${plan.flow}` : ''}&security=reality&sni=${plan.shareFront ? TLS_NAME : 'www.iij.ad.jp'}&fp=chrome&pbk=${RK_PUB}&type=tcp&sid=${SID}#${N}`;

function frontNode() {
  if (!plan.xhttp) return [];
  const name = urlEncode(plan.reality || plan.cfXhttp ? `${NAME}-xhttp` : NAME);
  const insecure = TLS_INSECURE ? `&allowInsecure=1&pcs=${PIN}` : '';
  return [`vless://${UUID}@${PUBLIC_ADDR}:${plan.direct}?encryption=none&security=tls&sni=${TLS_NAME}&fp=chrome&type=xhttp&host=${TLS_NAME}&path=${urlEncode(XHTTP_PATH)}&mode=auto${insecure}#${name}`];
}

function cfNode() {
  if (!plan.cfXhttp) return [];
  const name = urlEncode(plan.reality || plan.xhttp ? `${NAME}-cloudflare` : NAME);
  return [`vless://${UUID}@${CF_HOST}:443?encryption=none&security=tls&sni=${CF_HOST}&alpn=h2&fp=chrome&type=xhttp&host=${CF_HOST}&path=${urlEncode(XHTTP_PATH)}&mode=auto#${name}`];
}

const hy2Link = () => `hysteria2://${UUID}@${PUBLIC_ADDR}:${plan.hy2}/?sni=${TLS_NAME}${TLS_INSECURE ? '&insecure=1' : ''}#${N}`;
const mixedLinks = () => ['socks5', 'http'].map((s) => `${s}://${UUID}:${UUID}@${PUBLIC_ADDR}:${plan.mixed}#${N}`).join('\n');
const wgLink = () => `wireguard://${urlEncode(WGK.cpriv)}@${PUBLIC_ADDR}:${plan.wg}?publickey=${urlEncode(WGK.spub)}&address=${urlEncode(WG_CLIENT_ADDR)}&mtu=1420#${N}`;
const wgConfig = () => `[Interface]\nPrivateKey = ${WGK.cpriv}\nAddress = ${WG_CLIENT_ADDR}\nDNS = 1.1.1.1\nMTU = 1420\n\n[Peer]\nPublicKey = ${WGK.spub}\nEndpoint = ${PUBLIC_ADDR}:${plan.wg}\nAllowedIPs = 0.0.0.0/0, ::/0\nPersistentKeepalive = 25\n`;

// ========== 内置 HTTP 服务(只提供首页和订阅) ==========
// sock 可以是端口号(直接网页模式)，也可以是 Xray 回落用的抽象套接字名
function startWeb(sock, subBody) {
  http.createServer((req, res) => {
    const pathname = req.url.split('?')[0];
    const isGet = req.method === 'GET' || req.method === 'HEAD';
    const send = (status, type, body) => {
      res.writeHead(status, { 'Content-Type': type, 'Cache-Control': 'no-store' });
      res.end(req.method === 'HEAD' ? undefined : body);
    };
    if (isGet && subBody && pathname === `/${UUID}`) return send(200, 'text/plain; charset=utf-8', subBody);
    if (isGet && pathname === '/') {
      const index = readText(path.join(BASE_DIR, 'index.html'));
      return index ? send(200, 'text/html; charset=utf-8', index) : send(200, 'text/plain; charset=utf-8', 'Hello, World!\n');
    }
    send(404, 'text/plain; charset=utf-8', 'Not Found');
  }).on('error', (e) => console.error(`[WEB] HTTP service failed: ${e.message}`))
    .listen(typeof sock === 'number' ? sock : abs(sock));
}

// ========== 外部程序 ==========
async function startKomari() {
  const svc = `svc-k${hp}`;
  await killPrevious(svc, 'KOMARI');
  const bin = await fetchBin(svc, `https://github.com/komari-monitor/komari-agent/releases/latest/download/komari-agent-linux-${ARCH}`);
  const extra = { AGENT_ENDPOINT: KOMARI_EP, AGENT_TOKEN: KOMARI_TOKEN };
  if (plan.xray || plan.direct) {
    spawnBg(bin, [], LOG === 'none' ? '/dev/null' : path.join(WORK, `${svc}.log`), extra);
    return console.log(`[KOMARI] Agent started, reporting to ${KOMARI_EP}`);
  }
  console.log(`[KOMARI] No proxy protocol enabled, running the agent only, reporting to ${KOMARI_EP}`);
  const child = cp.spawn(bin, [], { env: { ...process.env, ...GO_ENV, ...extra }, stdio: STDIO });
  children.push(child);
  child.on('exit', (code) => process.exit(code ?? 1));
  await new Promise(() => {});
}

// 从 cloudflared 日志取最后一条 "Updated to new configuration" 行
const lastConfigLine = (text) => text.split('\n').filter((l) => l.includes('Updated to new configuration')).pop() || '';

// 从 cloudflared 日志取第一条有具体域名、Service 为 http://localhost:端口 的 ingress 规则
function parseIngress(text) {
  const m = lastConfigLine(text).match(/config="(.*)" version=/);
  if (!m) return null;
  let cfg;
  try { cfg = JSON.parse(m[1].replace(/\\"/g, '"')); } catch { return null; }
  for (const r of cfg.ingress || []) {
    const s = r.hostname && !r.hostname.includes('*') && /^http:\/\/(?:localhost|127\.0\.0\.1):(\d+)$/.exec(r.service || '');
    if (s) return { hostname: r.hostname, port: s[1] };
  }
  return null;
}

// 轮询日志直到 pick 返回真值；超时(30 秒)则打印末尾 20 行并退出
async function waitForLog(logFile, pick, what) {
  for (let i = 0; i < 30; i++) {
    const v = pick(readText(logFile));
    if (v) return v;
    await sleep(1000);
  }
  const tail = readText(logFile).split('\n').slice(-20).join('\n');
  die(`[CF] Timed out after 30s waiting for ${what}. Last lines of ${logFile}:\n${tail}`);
}

async function startCloudflared() {
  const svc = `svc-c${hp}`;
  await killPrevious(svc, 'CF');
  console.log(`[CF] Protocol: ${CONFIG.CLOUDFLARE_PROTOCOL}`);
  const bin = await fetchBin(svc, `https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-${ARCH}`);
  cp.spawnSync(bin, ['--version'], { stdio: STDIO });
  const logFile = path.join(WORK, `${svc}.log`);
  if (plan.quick) {
    CF_PORT = await freePort([plan.direct, plan.reality, plan.mixed, plan.hy2, plan.wg]);
    uniquePorts([plan.reality, !plan.shareFront && plan.direct, plan.mixed, CF_PORT]);
    spawnBg(bin, ['--no-autoupdate', 'tunnel', '--protocol', CONFIG.CLOUDFLARE_PROTOCOL, '--url', `http://localhost:${CF_PORT}`], logFile);
    CF_HOST = await waitForLog(logFile, (t) => [...t.matchAll(/https:\/\/([a-z0-9-]+\.trycloudflare\.com)/g)]
      .map((m) => m[1]).find((h) => !h.startsWith('api.')) || '', 'the trycloudflare.com hostname');
    console.log(`[CF] Quick tunnel hostname: ${CF_HOST} (service port=${CF_PORT})`);
    console.log('[CF] Quick tunnel hostname changes on every start; subscription links must be refreshed. Use a fixed tunnel for production.');
  } else {
    spawnBg(bin, ['--no-autoupdate', 'tunnel', '--protocol', CONFIG.CLOUDFLARE_PROTOCOL, 'run'], logFile, { TUNNEL_TOKEN: TUNNEL });
    const text = await waitForLog(logFile, (t) => (t.includes('Updated to new configuration') ? t : ''), 'the tunnel configuration');
    const rule = parseIngress(text);
    if (!rule || !validPort(rule.port)) {
      const line = lastConfigLine(text).slice(0, 200);
      die(`[CF] Cannot read hostname / port from ${logFile} (needs a Public hostname without * and a Service like http://localhost:PORT), exiting.\n` +
        `[CF] Matched config line (first 200 chars): ${line || '(none)'}`);
    }
    CF_HOST = rule.hostname;
    CF_PORT = +rule.port;
    uniquePorts([plan.reality, !plan.shareFront && plan.direct, plan.mixed, CF_PORT]);
    console.log(`[CF] From cloudflared log: hostname=${CF_HOST}, tunnel service port=${CF_PORT}`);
  }
  if (LOG === 'none') fs.rmSync(logFile, { force: true });
}

// ========== 主流程 ==========
async function main() {
  plan = makePlan();
  if (plan.xray && !UUID) die('[CONFIG] UUID is required for Xray, set it in the environment or in .env');

  if (plan.xhttp || plan.cfXhttp || plan.reality) console.log(`[MODE] enabled=vless${plan.xhttp ? ' xhttp' : ''}${plan.cfXhttp ? ' cloudflare' : ''}${plan.reality ? ' reality' : ''}`);
  if (plan.direct) console.log(`[MODE] port ${plan.direct}: web${plan.xhttp ? ' + xhttp' : ''}${plan.shareFront ? ' shared with reality' : ''}`);
  if (plan.tunnel) console.log(`[MODE] cloudflare tunnel (${plan.quick ? 'quick' : 'fixed'}): web${plan.cfXhttp ? ' + xhttp' : ''} (tunnel port decided by cloudflared log)`);
  if (plan.reality) console.log(`[MODE] port ${plan.reality}: reality`);
  if (!plan.xray && !plan.komari && !plan.direct) die('[MODE] Nothing to run: set PORT, CLOUDFLARE_TUNNEL_TOKEN, VLESS_MODE / HYSTERIA2_MODE / MIXED_MODE / WIREGUARD_MODE, or KOMARI_ENDPOINT + KOMARI_TOKEN');

  // 只有网页(无代理协议)：直接在 PORT 上提供网页，不需要 UUID，不下载 Xray
  if (!plan.xray) {
    if (plan.direct) startWeb(plan.direct, '');
    if (plan.komari) await startKomari();
    console.log('[MODE] No proxy protocol enabled, serving web page only');
    return;
  }

  if (plan.komari) await startKomari();

  if (plan.reality) {
    [RK_PRIV, RK_PUB] = deriveKey('reality', 'base64url');
    SID = sha256(`reality-short-id:${UUID}`).slice(0, 8);
    console.log(`[REALITY] Private key: ${RK_PRIV}\n[REALITY] Public key: ${RK_PUB}\n[REALITY] Short ID: ${SID}`);
  }
  if (plan.wg) {
    const [sp, spub] = deriveKey('wg-server', 'base64'), [cpriv, cpub] = deriveKey('wg-client', 'base64');
    WGK = { sp, spub, cpriv, cpub };
  }

  if (plan.net) await resolveAddr();
  IPV6 = await request(TRACE, { family: 6, timeout: 5000 }).then(() => true, () => false);
  console.log(IPV6 ? '[NET] IPv6 egress: available' : '[NET] IPv6 egress: unavailable, blocking IPv6 destinations');
  if (plan.tls) setupTls();
  if (plan.tunnel) await startCloudflared();

  // Xray
  const xrayBin = path.join(WORK, `xray-${hp}`), cfgFile = path.join(WORK, 'config.json'), zip = path.join(WORK, 'xray.zip');
  await killPrevious(`xray-${hp}`, 'XRAY');
  if (!await download(zip, `https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-${ARCH === 'amd64' ? '64' : 'arm64-v8a'}.zip`)) process.exit(1);
  await unzip(zip, WORK);
  fs.rmSync(zip, { force: true });
  try { fs.renameSync(path.join(WORK, 'xray'), xrayBin); } catch (e) { console.error(`[XRAY] Cannot rename binary: ${e.message}`); }
  if (!nonEmpty(xrayBin)) die(`[XRAY] Binary not found after extraction: ${xrayBin}`);
  fs.chmodSync(xrayBin, 0o755);
  const xrayEnv = { ...process.env, ...GO_ENV, XRAY_LOCATION_ASSET: WORK };

  // 先以 600 权限写入(含 UUID 和 Reality 私钥)，再测试配置
  fs.writeFileSync(cfgFile, `${JSON.stringify(buildConfig(), null, 2)}\n`, { mode: 0o600 });
  fs.chmodSync(cfgFile, 0o600);
  if (cp.spawnSync(xrayBin, ['run', '-test', '-c', cfgFile], { stdio: STDIO, env: xrayEnv }).status !== 0) die('[XRAY] Config test failed, aborting');

  // 订阅输出
  const allNodes = [plan.reality && realityLink(), ...frontNode(), ...cfNode(), plan.hy2 && hy2Link(), plan.wg && wgLink(), plan.mixed && mixedLinks()]
    .filter(Boolean).map((n) => `${n}\n`).join('');
  const subscription = Buffer.from(allNodes).toString('base64');
  console.log(`\n=== Nodes ===\n${allNodes}\n=== Subscription (base64) ===\n${subscription}\n`);
  if (plan.wg) console.log(`\n=== WireGuard config (wg-quick) ===\n${wgConfig()}`);
  if (plan.web) {
    const sub = allNodes ? subscription : '';
    if (plan.direct) startWeb(SOCK.web, sub);
    if (plan.tunnel) startWeb(SOCK['tunnel-web'], sub);
    const bases = [];
    if (plan.tunnel && CF_HOST) bases.push(`https://${CF_HOST}`);
    if (plan.direct) bases.push(`${plan.frontTls ? 'https' : 'http'}://${PUBLIC_ADDR}:${plan.direct}`);
    if (allNodes && bases.length) console.log(`\n=== Subscription URL ===\n${bases.map((b) => `${b}/${UUID}`).join('\n')}${plan.frontTls && TLS_INSECURE ? '\n(Self-signed certificate: clients must allow insecure TLS)' : ''}\n`);
  }

  // systemd 服务文件(限制 Node 自身堆内存)
  const svcName = `cache-${uuidHash.slice(0, 6)}`, svcFile = path.join(WORK, `${svcName}.service`);
  fs.writeFileSync(svcFile, `[Unit]\nDescription=${svcName}\nAfter=network.target\n\n[Service]\nType=simple\nRestart=always\nRestartSec=5\nWorkingDirectory=${WORK}\nExecStart=${process.execPath} --max-old-space-size=48 ${path.resolve(process.argv[1])}\nKillMode=mixed\nKillSignal=SIGTERM\n\n[Install]\nWantedBy=multi-user.target\n`);
  console.log(`\n=== systemd service (${svcName}) ===\ncp ${svcFile} /etc/systemd/system/${svcName}.service\nsystemctl daemon-reload && systemctl enable --now ${svcName}`);

  const xray = cp.spawn(xrayBin, ['run', '-c', cfgFile], { stdio: STDIO, env: xrayEnv });
  children.push(xray);
  xray.on('exit', (code) => process.exit(code ?? 1));
}

main().catch((e) => { console.error(e); process.exit(1); });
