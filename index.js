#!/usr/bin/env node
'use strict';
// 纯 Node.js(>=16)，除自签证书需要系统 openssl 外仅使用内置模块
const req = (m) => (typeof require === 'function' ? require(m) : process.getBuiltinModule(`node:${m}`));
const crypto = req('crypto'), fs = req('fs'), path = req('path'), cp = req('child_process');
const https = req('https'), http = req('http'), zlib = req('zlib'), dns = req('dns'), tls = req('tls');
const { X509Certificate } = crypto, { pipeline } = req('stream').promises;
const SCRIPT_PATH = path.resolve(process.argv[1]), BASE_DIR = path.dirname(SCRIPT_PATH), ENV_FILE = path.join(BASE_DIR, '.env');
const readText = (f) => { try { return fs.readFileSync(f, 'utf8'); } catch { return ''; } };
loadEnv(ENV_FILE);

const getEnv = (key, def = '') => (process.env[key] ?? def).trim();
const getEnvMode = (key, def = '') => getEnv(key, def).toLowerCase();

// ========== 用户配置(优先级：环境变量 > 同目录 .env > 默认值) ==========
// VLESS_MODE 写法：xhttp / 端口号(Reality)，多个用逗号分隔。配置了 CLOUDFLARE_TUNNEL_TOKEN 时 xhttp 走 Cloudflare Tunnel
const CONFIG = {
  NAME: getEnv('NAME', ''),
  UUID: getEnv('UUID', ''),
  CLOUDFLARE_TUNNEL_TOKEN: getEnv('CLOUDFLARE_TUNNEL_TOKEN', ''),
  CLOUDFLARE_IP: getEnv('CLOUDFLARE_IP', 'www.gov.tw'),
  PORT: getEnv('PORT', ''),
  CERT_HOST: getEnv('CERT_HOST', ''),
  VLESS_MODE: getEnvMode('VLESS_MODE', ''),
  HYSTERIA2_MODE: getEnv('HYSTERIA2_MODE', ''),
  MIXED_MODE: getEnv('MIXED_MODE'),
  WIREGUARD_MODE: getEnv('WIREGUARD_MODE'),
  WORK_DIR: getEnv('WORK_DIR', './'),
  KOMARI_ENDPOINT: getEnv('KOMARI_ENDPOINT', ''),
  KOMARI_TOKEN: getEnv('KOMARI_TOKEN', ''),
  LOG_LEVEL: getEnvMode('LOG_LEVEL', 'warning'),
};
normalizeConfig();
const { NAME, UUID, CLOUDFLARE_TUNNEL_TOKEN, CLOUDFLARE_IP, PORT, VLESS_MODE,
  HYSTERIA2_MODE, MIXED_MODE, WIREGUARD_MODE, CERT_HOST, KOMARI_ENDPOINT, KOMARI_TOKEN, LOG_LEVEL } = CONFIG;

for (const k of ['VMESS_MODE', 'TROJAN_MODE', 'SHADOWSOCKS_MODE']) {
  if (getEnv(k)) console.error(`[MODE] ${k} is no longer supported and is ignored`);
}

const QUIET = LOG_LEVEL === 'none';
if (QUIET) console.log = console.error = () => {};
const STDIO = QUIET ? 'ignore' : 'inherit';
const uuidHash = crypto.createHash('sha256').update(UUID).digest('hex'), hp = uuidHash.slice(0, 4);
const ARCH = { x64: 'amd64', arm64: 'arm64' }[process.arch];

console.log('[ENV]', Object.entries(CONFIG).filter(([, v]) => v).map(([k, v]) => `${k}=${/UUID|TOKEN/.test(k) ? `${v.slice(0, 4)}***` : v}`).join(' '));

const die = (msg) => { console.error(msg); process.exit(1); };
let WORK_DIR = '';
for (const dir of [...(CONFIG.WORK_DIR ? [path.resolve(BASE_DIR, CONFIG.WORK_DIR)] : []), `/var/lib/.cache${hp}`, `/tmp/.cache${hp}`]) {
  try { fs.mkdirSync(dir, { recursive: true }); fs.accessSync(dir, fs.constants.R_OK | fs.constants.W_OK); WORK_DIR = dir; break; }
  catch (e) { console.error(`[DIR] Cannot access ${dir}: ${e.message}`); }
}
if (!WORK_DIR) process.exit(1);
console.log(`[DIR] Work directory: ${WORK_DIR}`);
process.chdir(WORK_DIR);
if (!ARCH) die(`[ARCH] Unsupported architecture: ${process.arch}`);

// ========== 通用函数 ==========
function loadEnv(f) {
  try { return process.loadEnvFile(f); } catch (e) { if (e.code === 'ENOENT') return; }
  for (const line of readText(f).split(/\r?\n/)) {
    const m = line.match(/^\s*(?:export\s+)?([A-Za-z_]\w*)\s*=\s*(.*)$/);
    if (!m || line.trim().startsWith('#')) continue;
    const raw = m[2].trim(), q = raw.match(/^(['"])(.*?)\1/);
    if (process.env[m[1]] === undefined) process.env[m[1]] = q ? q[2] : raw.replace(/\s+#.*$/, '');
  }
}
// UUID 必须由用户提供：自动生成的 UUID 不会保存，每次启动都会变，订阅链接随之失效
function normalizeConfig() {
  if (!CONFIG.UUID) {
    console.error('[CONFIG] UUID is required, set it in the environment or in .env (e.g. node -e "console.log(crypto.randomUUID())")');
    process.exit(1);
  }
  CONFIG.PORT = CONFIG.PORT.replace(/^0+$/, '');
  CONFIG.CERT_HOST = CONFIG.CERT_HOST.replace(/^[a-z]+:\/\//i, '').replace(/[/:].*$/, '');
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const validPort = (v) => /^\d+$/.test(v) && +v >= 1 && +v <= 65535;
const nonEmpty = (f) => { try { return fs.statSync(f).size > 0; } catch { return false; } };
const urlEncode = (t) => encodeURIComponent(t).replace(/[!'()*]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`);
const IPV4 = /^\d{1,3}(\.\d{1,3}){3}$/;
const TRACE_URL = 'https://one.one.one.one/cdn-cgi/trace';

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
      res.on('data', (c) => chunks.push(c)).on('end', () => resolve({ status: code, body: Buffer.concat(chunks).toString() })).on('error', reject);
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

// 流式解压 zip：只读中央目录，逐文件解压
async function unzip(zipPath, targetDir) {
  const root = path.resolve(targetDir), fd = fs.openSync(zipPath, 'r'), size = fs.fstatSync(fd).size;
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
      const lh = readAt(30, offset);
      const start = offset + 30 + lh.readUInt16LE(26) + lh.readUInt16LE(28);
      await pipeline(fs.createReadStream(zipPath, { start, end: start + csize - 1 }),
        ...(method === 0 ? [] : [zlib.createInflateRaw()]), fs.createWriteStream(dest));
    }
  } finally { fs.closeSync(fd); }
}

// Go 内存参数：有容器内存限制时交给 GOMEMLIMIT 统一管理，否则 GOGC=50 省内存
const GO_ENV = (() => {
  const limit = +(readText('/sys/fs/cgroup/memory.max').trim() || readText('/sys/fs/cgroup/memory/memory.limit_in_bytes').trim());
  return limit > 0 && limit < 2 ** 40 ? { GOGC: 'off', GOMEMLIMIT: `${Math.floor(limit * 0.6 / 1048576)}MiB` } : { GOGC: '50' };
})();

const childProcesses = [];
process.on('exit', () => childProcesses.forEach((c) => { try { c.kill(); } catch {} }));
for (const sig of ['SIGINT', 'SIGTERM']) process.on(sig, () => process.exit(0));

async function killPrevious(name, tag) {
  try { cp.execFileSync('pkill', ['-x', name], { stdio: 'ignore' }); } catch { return; }
  console.log(`[${tag}] Stopped previous ${name}`);
  await sleep(1000);
}

function spawnBackground(bin, args, logFile, extra = {}) {
  const fd = fs.openSync(logFile, 'w');
  const child = cp.spawn(bin, args, { env: { ...process.env, ...GO_ENV, ...extra }, stdio: ['ignore', fd, fd] });
  fs.closeSync(fd);
  childProcesses.push(child);
  return child;
}

// ========== 协议与端口 ==========
const XHTTP_PATH = `/${UUID}-vless-xhttp`;
const abstractSock = (n) => `@xray-${crypto.createHash('sha1').update(BASE_DIR).digest('hex').slice(0, 8)}-${n}`;
const XHTTP_SOCKET = abstractSock('vless-xhttp'), FRONT_SOCKET = abstractSock('front'), WEB_SOCKET = abstractSock('web');
const QUICK_TUNNEL_PORT = 8000, WG_CLIENT_ADDR = '10.0.0.2/32';
const ENCODED_NAME = urlEncode(NAME);

// 前置入口的非 xhttp 请求回落到内置 HTTP 服务
const WEB_DEST = PORT && CERT_HOST ? `${CERT_HOST}:80` : '';
if (WEB_DEST) {
  if (!/^[A-Za-z0-9.-]+:\d{1,5}$/.test(WEB_DEST)) die(`[WEB] CERT_HOST='${CERT_HOST}' is invalid (expected a domain or an IPv4 address)`);
  console.log(`[WEB] Other paths on the front port are forwarded to ${WEB_DEST}`);
}

const modePort = (name, v, desc) => {
  if (!v) return 0;
  if (!validPort(v)) die(`[MODE] ${name}='${v}' is invalid (expected a port 1-65535, or empty to disable)`);
  console.log(`[MODE] port ${+v}/${desc}`);
  return +v;
};
const HY2_PORT = modePort('HYSTERIA2_MODE', HYSTERIA2_MODE, 'udp: hysteria2');
const MIXED_PORT = modePort('MIXED_MODE', MIXED_MODE, 'tcp: mixed (socks5 + http)');
const WG_PORT = modePort('WIREGUARD_MODE', WIREGUARD_MODE, 'udp: wireguard');

// VLESS_MODE：xhttp / 端口号(Reality)，逗号分隔
let XHTTP_ON = false, REALITY_PORT = 0;
for (const t of VLESS_MODE.split(',').map((s) => s.trim()).filter(Boolean)) {
  if (t === 'ws' || t === 'cloudflare') die(`[MODE] VLESS_MODE: '${t}' is no longer supported, use xhttp (with CLOUDFLARE_TUNNEL_TOKEN for Cloudflare Tunnel)`);
  if (t === 'xhttp') {
    if (XHTTP_ON) die("[MODE] VLESS_MODE: 'xhttp' is given more than once");
    XHTTP_ON = true;
  } else if (/^\d+$/.test(t)) {
    if (!validPort(t)) die(`[MODE] VLESS_MODE='${t}': port must be 1-65535`);
    if (REALITY_PORT) die('[MODE] VLESS_MODE: only one Reality port is allowed');
    REALITY_PORT = +t;
  } else die(`[MODE] VLESS_MODE='${t}' is invalid (expected xhttp or a port)`);
}

// 运行时状态
let CF_ON = false, FRONT_ON = false, SHARE_FRONT = false, FRONT_TLS = false, FRONT_PORT = 0, CF_PORT = 0;
let XRAY_ON = false, CF_HOSTNAME = '', PUBLIC_ADDRESS = '', VLESS_FLOW = '', IPV6_AVAILABLE = false;
let REALITY_PRIVATE_KEY = '', REALITY_PUBLIC_KEY = '', REALITY_SHORT_ID = '';
let WG_SERVER_PRIV = '', WG_SERVER_PUB = '', WG_CLIENT_PRIV = '', WG_CLIENT_PUB = '';
let CERT_FILE = '', KEY_FILE = '', TLS_SERVER_NAME = '', TLS_INSECURE = true, PIN = '';

function checkPorts() {
  const used = [REALITY_PORT, FRONT_ON && !CF_ON && !SHARE_FRONT && FRONT_PORT, CF_PORT, MIXED_PORT].filter(Boolean);
  const dup = used.find((p, i) => used.indexOf(p) !== i);
  if (dup !== undefined) die(`[MODE] Port ${dup} is used more than once`);
}

// ========== TLS 证书 ==========
// 自签证书(RSA 2048，10 年)；已有且 30 天内不过期则复用
function generateSelfSignedCert(cn) {
  const dir = path.join(WORK_DIR, '.selfsigned');
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

// 校验证书链：域名匹配、逐级验签、最终落在系统信任根上；返回空串表示可信
function verifyChain(chain, hostname) {
  if (!chain[0].checkHost(hostname)) return 'hostname mismatch';
  const roots = (tls.getCACertificates ? tls.getCACertificates('default') : tls.rootCertificates).map((pem) => new X509Certificate(pem));
  const now = Date.now();
  const valid = (c) => now >= Date.parse(c.validFrom) && now <= Date.parse(c.validTo);
  const signedBy = (c, issuer) => c.checkIssued(issuer) && c.verify(issuer.publicKey);
  let cur = chain[0];
  for (let depth = 0; depth < 8; depth++) {
    if (!valid(cur)) return 'certificate expired or not yet valid';
    if (roots.some((root) => root.fingerprint256 === cur.fingerprint256 || (valid(root) && signedBy(cur, root)))) return '';
    cur = chain.slice(1).find((issuer) => issuer !== cur && issuer.ca && signedBy(cur, issuer));
    if (!cur) return 'issuer is not trusted';
  }
  return 'chain too long';
}

function trustedCertForHost(hostname) {
  const certFile = path.join(WORK_DIR, `${hostname}.crt`), keyFile = path.join(WORK_DIR, `${hostname}.key`);
  if (!nonEmpty(certFile) || !nonEmpty(keyFile)) return false;
  let chain;
  try {
    chain = (fs.readFileSync(certFile, 'utf8').match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g) || [])
      .map((pem) => new X509Certificate(pem));
    if (!chain.length || !chain[0].checkPrivateKey(crypto.createPrivateKey(fs.readFileSync(keyFile)))) throw new Error('no matching certificate and key');
  } catch (e) { console.error(`[TLS] Cannot read ${certFile} / ${keyFile}: ${e.message}`); return false; }
  const reason = verifyChain(chain, hostname);
  if (reason) { console.error(`[TLS] ${certFile} is not trusted for ${hostname}: ${reason}`); return false; }
  CERT_FILE = certFile;
  KEY_FILE = keyFile;
  return true;
}

function setupTls() {
  TLS_SERVER_NAME = CERT_HOST || 'www.nazhumi.com';
  TLS_INSECURE = !(CERT_HOST && !IPV4.test(CERT_HOST) && trustedCertForHost(CERT_HOST));
  if (TLS_INSECURE) {
    console.error(`[TLS] No trusted certificate (put one at ${WORK_DIR}/<CERT_HOST>.crt and .key), using self-signed certificate`);
    generateSelfSignedCert(TLS_SERVER_NAME);
    PIN = new X509Certificate(fs.readFileSync(CERT_FILE)).fingerprint256.replace(/:/g, '').toLowerCase();
  }
  console.log(`[TLS] Server name: ${TLS_SERVER_NAME}, insecure: ${TLS_INSECURE ? 1 : 0}, cert: ${CERT_FILE}`);
}

// ========== 密钥(由 UUID 派生，同一 UUID 永远得到同一组密钥) ==========
function deriveKey(label, encoding) {
  const priv = crypto.createHash('sha256').update(`${label}:${UUID}`).digest();
  priv[0] &= 248;
  priv[31] = (priv[31] & 127) | 64;
  const pub = crypto.createPublicKey(crypto.createPrivateKey({
    key: Buffer.concat([Buffer.from('302e020100300506032b656e04220420', 'hex'), priv]), format: 'der', type: 'pkcs8',
  })).export({ type: 'spki', format: 'der' }).subarray(-32);
  return [priv.toString(encoding), Buffer.from(pub).toString(encoding)];
}

async function resolvePublicAddress() {
  if (IPV4.test(CERT_HOST)) PUBLIC_ADDRESS = CERT_HOST;
  else {
    const trace = await request(TRACE_URL, { family: 4, timeout: 5000 }).catch(() => null);
    PUBLIC_ADDRESS = ((trace && trace.body.match(/^ip=(.*)$/m)) || [, ''])[1].trim();
    if (CERT_HOST && PUBLIC_ADDRESS) {
      const ips = await dns.promises.lookup(CERT_HOST, { family: 4, all: true }).then((es) => es.map((e) => e.address)).catch(() => []);
      if (ips.includes(PUBLIC_ADDRESS)) {
        console.log(`[NET] ${CERT_HOST} points to this server, using it instead of the IP`);
        PUBLIC_ADDRESS = CERT_HOST;
      }
    }
  }
  if (!PUBLIC_ADDRESS) console.error('[NET] Cannot determine the public address, links will be invalid (set CERT_HOST)');
  console.log(`[NET] Address in links: ${PUBLIC_ADDRESS}`);
}

// ========== Xray 配置 ==========
const SNIFFING = { enabled: true, destOverride: ['http', 'tls', 'quic'], routeOnly: true };
const inbound = (tag, listen, port, protocol, settings, stream) => ({ tag, listen, port, protocol, settings, streamSettings: stream, sniffing: SNIFFING });
const streamTcp = () => ({ network: 'tcp', security: 'none' });
const streamXhttp = () => ({ network: 'xhttp', security: 'none', xhttpSettings: { path: XHTTP_PATH, mode: 'auto' } });
const streamReality = (dest = 'www.iij.ad.jp:443', sn = 'www.iij.ad.jp') => ({
  network: 'tcp', security: 'reality',
  realitySettings: { show: false, dest, xver: 0, serverNames: [sn], privateKey: REALITY_PRIVATE_KEY, shortIds: [REALITY_SHORT_ID] },
});
const streamTls = (network, alpn, extra = {}) => ({
  network, security: 'tls',
  tlsSettings: { serverName: TLS_SERVER_NAME, alpn: [alpn], certificates: [{ certificateFile: CERT_FILE, keyFile: KEY_FILE }] },
  ...extra,
});
const vless = (fallbacks, flow) => ({
  clients: [{ id: UUID, email: UUID, ...(flow ? { flow } : {}) }], decryption: 'none', ...(fallbacks ? { fallbacks } : {}),
});

function buildConfig() {
  const ib = [];
  if (XHTTP_ON) ib.push(inbound('vless-xhttp-in', XHTTP_SOCKET, undefined, 'vless', vless(), streamXhttp()));
  if (FRONT_ON) {
    const fb = [...(XHTTP_ON ? [{ path: XHTTP_PATH, dest: XHTTP_SOCKET, xver: 0 }] : []), { dest: WEB_SOCKET, xver: 0 }];
    const [listen, port] = CF_ON ? ['::', CF_PORT] : SHARE_FRONT ? [FRONT_SOCKET, undefined] : ['::', FRONT_PORT];
    ib.push(inbound('front-in', listen, port, 'vless', vless(fb), FRONT_TLS ? streamTls('tcp', 'http/1.1') : streamTcp()));
  }
  if (REALITY_PORT) ib.push(inbound('vless-in', '::', REALITY_PORT, 'vless', vless(undefined, VLESS_FLOW),
    SHARE_FRONT ? streamReality(FRONT_SOCKET, TLS_SERVER_NAME) : streamReality()));
  if (HY2_PORT) ib.push(inbound('hysteria2-in', '::', HY2_PORT, 'hysteria',
    { version: 2, clients: [{ auth: UUID, email: UUID }] }, streamTls('hysteria', 'h3', { hysteriaSettings: { version: 2 } })));
  if (MIXED_PORT) ib.push(inbound('mixed-in', '::', MIXED_PORT, 'socks',
    { auth: 'password', accounts: [{ user: UUID, pass: UUID }], udp: false }, streamTcp()));
  if (WG_PORT) ib.push(inbound('wireguard-in', '::', WG_PORT, 'wireguard',
    { secretKey: WG_SERVER_PRIV, peers: [{ publicKey: WG_CLIENT_PUB, allowedIPs: [WG_CLIENT_ADDR] }], mtu: 1420 }));

  return {
    log: { loglevel: LOG_LEVEL },
    // 空闲连接 180 秒后回收，降低长期占用的连接数与内存
    policy: { levels: { 0: { handshake: 4, connIdle: 180, uplinkOnly: 2, downlinkOnly: 5 } } },
    dns: { servers: ['https+local://1.1.1.1/dns-query'], queryStrategy: 'UseIPv4' },
    inbounds: ib,
    outbounds: [{ tag: 'direct', protocol: 'freedom' }, { tag: 'block', protocol: 'blackhole' }],
    routing: {
      domainStrategy: 'IPIfNonMatch',
      rules: [
        { type: 'field', ip: ['geoip:private'], outboundTag: 'direct' },
        ...(IPV6_AVAILABLE ? [] : [{ type: 'field', ip: ['::/0'], outboundTag: 'block' }]),
        { type: 'field', domain: ['geosite:cn', 'geosite:category-ads-all'], outboundTag: 'block' },
        { type: 'field', ip: ['geoip:cn'], outboundTag: 'block' },
      ],
    },
  };
}

// ========== 订阅链接 ==========
const realityLink = () => {
  const sni = SHARE_FRONT ? TLS_SERVER_NAME : 'www.iij.ad.jp';
  const flow = VLESS_FLOW ? `&flow=${VLESS_FLOW}` : '';
  return `vless://${UUID}@${PUBLIC_ADDRESS}:${REALITY_PORT}?encryption=none${flow}&security=reality&sni=${sni}&fp=chrome&pbk=${REALITY_PUBLIC_KEY}&type=tcp&sid=${REALITY_SHORT_ID}#${ENCODED_NAME}`;
};

// 前置入口的连接参数：走 Cloudflare Tunnel 时用 CF 域名 443，否则用直连地址；无 CF 域名时不生成节点
function frontNodes() {
  if (!XHTTP_ON || (CF_ON && !CF_HOSTNAME)) return [];
  const p = CF_ON
    ? { address: CLOUDFLARE_IP || CF_HOSTNAME, port: 443, host: CF_HOSTNAME, query: '' }
    : { address: PUBLIC_ADDRESS, port: FRONT_PORT, host: TLS_SERVER_NAME, query: TLS_INSECURE ? `&allowInsecure=1&pcs=${PIN}` : '' };
  const name = REALITY_PORT ? `${NAME}-xhttp` : NAME;
  return [`vless://${UUID}@${p.address}:${p.port}?encryption=none&security=tls&sni=${p.host}&fp=chrome&type=xhttp&host=${p.host}&path=${urlEncode(XHTTP_PATH)}&mode=auto${p.query}#${urlEncode(name)}`];
}

const hy2Link = () => `hysteria2://${UUID}@${PUBLIC_ADDRESS}:${HY2_PORT}/?sni=${TLS_SERVER_NAME}${TLS_INSECURE ? '&insecure=1' : ''}#${ENCODED_NAME}`;
const mixedLinks = () => ['socks5', 'http'].map((s) => `${s}://${UUID}:${UUID}@${PUBLIC_ADDRESS}:${MIXED_PORT}#${ENCODED_NAME}`).join('\n');
const wgLink = () => `wireguard://${urlEncode(WG_CLIENT_PRIV)}@${PUBLIC_ADDRESS}:${WG_PORT}?publickey=${urlEncode(WG_SERVER_PUB)}&address=${urlEncode(WG_CLIENT_ADDR)}&mtu=1420#${ENCODED_NAME}`;
const wgConfig = () => `[Interface]\nPrivateKey = ${WG_CLIENT_PRIV}\nAddress = ${WG_CLIENT_ADDR}\nDNS = 1.1.1.1\nMTU = 1420\n\n[Peer]\nPublicKey = ${WG_SERVER_PUB}\nEndpoint = ${PUBLIC_ADDRESS}:${WG_PORT}\nAllowedIPs = 0.0.0.0/0, ::/0\nPersistentKeepalive = 25\n`;

// ========== 内置 HTTP 服务(订阅 + xhttp 转发 + 回落) ==========
// 复用到 Xray abstract socket / 回落目标的长连接，避免每个请求都新建连接
const upstreamAgent = new http.Agent({ keepAlive: true, keepAliveMsecs: 30000, maxSockets: 512 });

function startWeb(subscriptionBody) {
  const [destHost, destPort] = WEB_DEST.split(':');
  const xhttpSocketPath = `\0${XHTTP_SOCKET.slice(1)}`;
  http.createServer((req, res) => {
    const pathname = req.url.split('?')[0];
    const forward = (opts) => {
      const up = http.request({ ...opts, path: req.url, method: req.method, headers: req.headers, agent: upstreamAgent }, (ur) => {
        res.writeHead(ur.statusCode, ur.headers);
        ur.pipe(res);
      });
      up.on('error', () => { if (!res.headersSent) res.writeHead(502); res.end(); });
      req.pipe(up);
    };
    if (XHTTP_ON && (pathname === XHTTP_PATH || pathname.startsWith(`${XHTTP_PATH}/`))) return forward({ socketPath: xhttpSocketPath });
    if ((req.method === 'GET' || req.method === 'HEAD') && pathname === `/${UUID}`) {
      res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store' });
      return res.end(req.method === 'HEAD' ? undefined : subscriptionBody);
    }
    if (!WEB_DEST) { res.writeHead(404, { 'Content-Type': 'text/plain' }); return res.end('Not Found'); }
    forward({ host: destHost, port: +destPort, agent: false });
  }).on('error', (e) => console.error(`[WEB] HTTP service failed: ${e.message}`))
    .listen(`\0${WEB_SOCKET.slice(1)}`);
}

// ========== 外部程序 ==========
async function fetchBinary(name, url) {
  const bin = path.join(WORK_DIR, name);
  if (!await download(bin, url)) process.exit(1);
  fs.chmodSync(bin, 0o755);
  return bin;
}

async function startKomari() {
  const svc = `svc-k${hp}`;
  await killPrevious(svc, 'KOMARI');
  const bin = await fetchBinary(svc, `https://github.com/komari-monitor/komari-agent/releases/latest/download/komari-agent-linux-${ARCH}`);
  const agentEnv = { AGENT_ENDPOINT: KOMARI_ENDPOINT, AGENT_TOKEN: KOMARI_TOKEN };
  if (XRAY_ON) {
    spawnBackground(bin, [], QUIET ? '/dev/null' : path.join(WORK_DIR, `${svc}.log`), agentEnv);
    return console.log(`[KOMARI] Agent started, reporting to ${KOMARI_ENDPOINT}`);
  }
  console.log(`[KOMARI] No proxy protocol enabled, running the agent only, reporting to ${KOMARI_ENDPOINT}`);
  const child = cp.spawn(bin, [], { env: { ...process.env, ...GO_ENV, ...agentEnv }, stdio: STDIO });
  childProcesses.push(child);
  child.on('exit', (code) => process.exit(code ?? 1));
  await new Promise(() => {});
}

// 从 cloudflared 日志取第一条有具体域名、Service 为 http://localhost:端口 的 ingress 规则
function parseIngress(logText) {
  const m = logText.split('\n').filter((l) => l.includes('Updated to new configuration')).pop()?.match(/config="(.*)" version=/);
  if (!m) return null;
  let config;
  try { config = JSON.parse(m[1].replace(/\\"/g, '"')); } catch { return null; }
  for (const rule of config.ingress || []) {
    const s = rule.hostname && !rule.hostname.includes('*') && /^http:\/\/(?:localhost|127\.0\.0\.1):(\d+)$/.exec(rule.service || '');
    if (s) return { hostname: rule.hostname, port: s[1] };
  }
  return null;
}

async function startCloudflared() {
  const svc = `svc-c${hp}`;
  await killPrevious(svc, 'CF');
  const bin = await fetchBinary(svc, `https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-${ARCH}`);
  const logFile = path.join(WORK_DIR, `${svc}.log`);
  cp.spawnSync(bin, ['--version'], { stdio: STDIO });

  if (CLOUDFLARE_TUNNEL_TOKEN === 'try') {
    CF_PORT = QUICK_TUNNEL_PORT;
    checkPorts();
    spawnBackground(bin, ['--no-autoupdate', 'tunnel', '--url', `http://localhost:${CF_PORT}`], logFile);
    for (let i = 0; i < 30 && !CF_HOSTNAME; i++) {
      CF_HOSTNAME = [...readText(logFile).matchAll(/https:\/\/([a-z0-9-]+\.trycloudflare\.com)/g)]
        .map((m) => m[1]).find((h) => !h.startsWith('api.')) || '';
      if (!CF_HOSTNAME) await sleep(1000);
    }
    if (!CF_HOSTNAME) die(`[CF] Cannot find the trycloudflare.com hostname in ${logFile}, exiting`);
    console.log(`[CF] Quick tunnel hostname: ${CF_HOSTNAME} (service port=${CF_PORT})`);
  } else {
    spawnBackground(bin, ['--no-autoupdate', 'tunnel', 'run'], logFile, { TUNNEL_TOKEN: CLOUDFLARE_TUNNEL_TOKEN });
    for (let i = 0; i < 30 && !readText(logFile).includes('Updated to new configuration'); i++) await sleep(1000);
    const rule = parseIngress(readText(logFile));
    if (!rule || !validPort(rule.port)) die(`[CF] Cannot read hostname / port from ${logFile} (needs a Public hostname without * and a Service like http://localhost:PORT), exiting`);
    CF_HOSTNAME = rule.hostname;
    CF_PORT = +rule.port;
    checkPorts();
    console.log(`[CF] From cloudflared log: hostname=${CF_HOSTNAME}, tunnel service port=${CF_PORT}`);
  }
  if (QUIET) fs.rmSync(logFile, { force: true });
}

// ========== 主流程 ==========
async function main() {
  // 模式解析与前置入口规划
  if (!PORT && !CLOUDFLARE_TUNNEL_TOKEN && XHTTP_ON) {
    console.log('[MODE] PORT is empty: xhttp is disabled (set PORT, or CLOUDFLARE_TUNNEL_TOKEN)');
    XHTTP_ON = false;
  }
  CF_ON = !!CLOUDFLARE_TUNNEL_TOKEN && XHTTP_ON;
  FRONT_ON = CF_ON || !!PORT;
  if (CF_ON && PORT) console.log('[MODE] PORT is ignored: xhttp is served through the Cloudflare Tunnel');
  if (FRONT_ON && !CF_ON) {
    if (!validPort(PORT)) die(`[MODE] PORT='${PORT}' is not a valid port`);
    FRONT_PORT = +PORT;
  }
  SHARE_FRONT = !!REALITY_PORT && REALITY_PORT === FRONT_PORT;
  FRONT_TLS = !CF_ON && (XHTTP_ON || SHARE_FRONT);
  checkPorts();

  if (XHTTP_ON || REALITY_PORT) console.log(`[MODE] enabled=vless${XHTTP_ON ? ' xhttp' : ''}${REALITY_PORT ? ' reality' : ''}`);
  if (CF_ON) console.log(`[MODE] cloudflare tunnel (${CLOUDFLARE_TUNNEL_TOKEN === 'try' ? 'quick' : 'fixed'}): xhttp (tunnel port decided by cloudflared log)`);
  else if (FRONT_ON) console.log(`[MODE] port ${FRONT_PORT}: ${XHTTP_ON ? 'xhttp' : 'subscription only'}${SHARE_FRONT ? ' shared with reality' : ''}`);
  if (REALITY_PORT) console.log(`[MODE] port ${REALITY_PORT}: reality`);
  VLESS_FLOW = REALITY_PORT ? 'xtls-rprx-vision' : '';
  XRAY_ON = XHTTP_ON || !!REALITY_PORT || !!(HY2_PORT || MIXED_PORT || WG_PORT);

  const KOMARI_ON = !!(KOMARI_ENDPOINT && KOMARI_TOKEN);
  if (!XRAY_ON && !KOMARI_ON) die('[MODE] Nothing to run: set VLESS_MODE / HYSTERIA2_MODE / MIXED_MODE / WIREGUARD_MODE, or KOMARI_ENDPOINT + KOMARI_TOKEN');
  if (KOMARI_ON) await startKomari();

  if (REALITY_PORT) {
    [REALITY_PRIVATE_KEY, REALITY_PUBLIC_KEY] = deriveKey('reality', 'base64url');
    REALITY_SHORT_ID = crypto.createHash('sha256').update(`reality-short-id:${UUID}`).digest('hex').slice(0, 8);
    console.log(`[REALITY] Private key: ${REALITY_PRIVATE_KEY}\n[REALITY] Public key: ${REALITY_PUBLIC_KEY}\n[REALITY] Short ID: ${REALITY_SHORT_ID}`);
  }
  if (WG_PORT) {
    [WG_SERVER_PRIV, WG_SERVER_PUB] = deriveKey('wg-server', 'base64');
    [WG_CLIENT_PRIV, WG_CLIENT_PUB] = deriveKey('wg-client', 'base64');
  }

  if ((FRONT_ON && !CF_ON) || REALITY_PORT || HY2_PORT || MIXED_PORT || WG_PORT) await resolvePublicAddress();
  IPV6_AVAILABLE = await request(TRACE_URL, { family: 6, timeout: 5000 }).then(() => true, () => false);
  console.log(IPV6_AVAILABLE ? '[NET] IPv6 egress: available' : '[NET] IPv6 egress: unavailable, blocking IPv6 destinations');
  if (FRONT_TLS || HY2_PORT) setupTls();
  if (CF_ON) await startCloudflared();

  // ---- Xray ----
  const xrayBin = path.join(WORK_DIR, `xray-${hp}`), configFile = path.join(WORK_DIR, 'config.json');
  const zipFile = path.join(WORK_DIR, 'xray.zip');
  await killPrevious(`xray-${hp}`, 'XRAY');
  if (!await download(zipFile, `https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-${ARCH === 'amd64' ? '64' : 'arm64-v8a'}.zip`)) process.exit(1);
  await unzip(zipFile, WORK_DIR);
  fs.rmSync(zipFile, { force: true });
  try { fs.renameSync(path.join(WORK_DIR, 'xray'), xrayBin); } catch (e) { console.error(`[XRAY] Cannot rename binary: ${e.message}`); }
  if (!nonEmpty(xrayBin)) die(`[XRAY] Binary not found after extraction: ${xrayBin}`);
  fs.chmodSync(xrayBin, 0o755);
  const xrayEnv = { ...process.env, ...GO_ENV, XRAY_LOCATION_ASSET: WORK_DIR };

  // 先以 600 权限写入(含 UUID 和 Reality 私钥)，再测试配置
  fs.writeFileSync(configFile, `${JSON.stringify(buildConfig(), null, 2)}\n`, { mode: 0o600 });
  fs.chmodSync(configFile, 0o600);
  if (cp.spawnSync(xrayBin, ['run', '-test', '-c', configFile], { stdio: STDIO, env: xrayEnv }).status !== 0) die('[XRAY] Config test failed, aborting');

  // ---- 订阅输出 ----
  const allNodes = [REALITY_PORT && realityLink(), ...frontNodes(), HY2_PORT && hy2Link(), WG_PORT && wgLink(), MIXED_PORT && mixedLinks()]
    .filter(Boolean).map((n) => `${n}\n`).join('');
  const subscription = Buffer.from(allNodes).toString('base64');
  console.log(`\n=== Nodes ===\n${allNodes}\n=== Subscription (base64) ===\n${subscription}\n`);
  if (WG_PORT) console.log(`\n=== WireGuard config (wg-quick) ===\n${wgConfig()}`);
  if (FRONT_ON) {
    startWeb(subscription);
    const bases = CF_ON ? (CF_HOSTNAME ? [`https://${CF_HOSTNAME}`] : []) : [`${FRONT_TLS ? 'https' : 'http'}://${PUBLIC_ADDRESS}:${FRONT_PORT}`];
    if (bases.length) console.log(`\n=== Subscription URL ===\n${bases.map((b) => `${b}/${UUID}`).join('\n')}${FRONT_TLS && TLS_INSECURE ? '\n(自签证书：客户端需要允许不校验证书)' : ''}\n`);
  }

  // ---- systemd 服务文件(限制 Node 自身堆内存) ----
  const serviceName = `cache-${uuidHash.slice(0, 6)}`, serviceFile = path.join(WORK_DIR, `${serviceName}.service`);
  fs.writeFileSync(serviceFile, `[Unit]\nDescription=${serviceName}\nAfter=network.target\n\n[Service]\nType=simple\nRestart=always\nRestartSec=5\nWorkingDirectory=${WORK_DIR}\nExecStart=${process.execPath} --max-old-space-size=48 ${SCRIPT_PATH}\nKillMode=mixed\nKillSignal=SIGTERM\n\n[Install]\nWantedBy=multi-user.target\n`);
  console.log(`\n=== systemd service (${serviceName}) ===\ncp ${serviceFile} /etc/systemd/system/${serviceName}.service\nsystemctl daemon-reload && systemctl enable --now ${serviceName}`);

  const xrayProcess = cp.spawn(xrayBin, ['run', '-c', configFile], { stdio: STDIO, env: xrayEnv });
  childProcesses.push(xrayProcess);
  xrayProcess.on('exit', (code) => process.exit(code ?? 1));
}

main().catch((e) => { console.error(e); process.exit(1); });
