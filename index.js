#!/usr/bin/env node
'use strict';
// 纯 Node.js(>=16)，除自签证书需要系统 openssl 外仅使用内置模块
const req = (m) => (typeof require === 'function' ? require(m) : process.getBuiltinModule(`node:${m}`));
const [crypto, fs, path, cp, https, http, zlib, dns, tls] = ['crypto', 'fs', 'path', 'child_process', 'https', 'http', 'zlib', 'dns', 'tls'].map(req);
const { X509Certificate } = crypto;
const { pipeline } = req('stream').promises;
const SELF = path.resolve(process.argv[1]), BASE_DIR = path.dirname(SELF);
loadEnv(path.join(BASE_DIR, '.env'));

const env = (k, d = '') => (process.env[k] ?? d).trim();
const mode = (k, d = '') => env(k, d).toLowerCase();

// ========== 用户配置(优先级：环境变量 > 同目录 .env > 默认值) ==========
const CONFIG = {
  NAME: env('NAME'),
  UUID: env('UUID'),
  CLOUDFLARE_TUNNEL_TOKEN: env('CLOUDFLARE_TUNNEL_TOKEN'),
  CLOUDFLARE_IP: env('CLOUDFLARE_IP', 'www.gov.tw'),
  PORT: env('PORT'),
  CERT_HOST: env('CERT_HOST'),
  VLESS_MODE: mode('VLESS_MODE', 'trojan'),
  VMESS_MODE: mode('VMESS_MODE'),
  TROJAN_MODE: mode('TROJAN_MODE', 'vmess'),
  SHADOWSOCKS_MODE: mode('SHADOWSOCKS_MODE'),
  HYSTERIA2_MODE: env('HYSTERIA2_MODE'),
  MIXED_MODE: env('MIXED_MODE'),
  WIREGUARD_MODE: env('WIREGUARD_MODE'),
  WORK_DIR: env('WORK_DIR'),
  KOMARI_ENDPOINT: env('KOMARI_ENDPOINT'),
  KOMARI_TOKEN: env('KOMARI_TOKEN'),
  LOG_LEVEL: mode('LOG_LEVEL', 'warning'),
};
normalizeConfig();
if (CONFIG.LOG_LEVEL !== 'none') persistEnv(path.join(BASE_DIR, '.env'));
const { NAME, UUID, CLOUDFLARE_TUNNEL_TOKEN, CLOUDFLARE_IP, PORT, VLESS_MODE, VMESS_MODE, TROJAN_MODE, SHADOWSOCKS_MODE,
  HYSTERIA2_MODE, MIXED_MODE, WIREGUARD_MODE, CERT_HOST, KOMARI_ENDPOINT, KOMARI_TOKEN, LOG_LEVEL } = CONFIG;

const QUIET = LOG_LEVEL === 'none';
if (QUIET) console.log = console.error = () => {};
const STDIO = QUIET ? 'ignore' : 'inherit';
const uuidHash = crypto.createHash('sha256').update(UUID).digest('hex');
const h4 = uuidHash.slice(0, 4);
const ARCH = { x64: 'amd64', arm64: 'arm64' }[process.arch];

console.log('[ENV]', Object.entries(CONFIG).filter(([, v]) => v).map(([k, v]) => `${k}=${/UUID|TOKEN/.test(k) ? `${v.slice(0, 4)}***` : v}`).join(' '));

let WORK_DIR = '';
for (const dir of [...(CONFIG.WORK_DIR ? [path.resolve(BASE_DIR, CONFIG.WORK_DIR)] : []), `/var/lib/.cache${h4}`, `/tmp/.cache${h4}`]) {
  try { fs.mkdirSync(dir, { recursive: true }); fs.accessSync(dir, fs.constants.R_OK | fs.constants.W_OK); WORK_DIR = dir; break; }
  catch (e) { console.error(`[DIR] Cannot access ${dir}: ${e.message}`); }
}
if (!WORK_DIR) process.exit(1);
console.log(`[DIR] Work directory: ${WORK_DIR}`);
process.chdir(WORK_DIR);
if (!ARCH) die(`[ARCH] Unsupported architecture: ${process.arch}`);

// ========== 通用函数 ==========
function die(msg) { console.error(msg); process.exit(1); }
function readLog(file) { try { return fs.readFileSync(file, 'utf8'); } catch { return ''; } }
function loadEnv(file) {
  try { return process.loadEnvFile(file); } catch (e) { if (e.code === 'ENOENT') return; }
  for (const line of readLog(file).split(/\r?\n/)) {
    const m = line.match(/^\s*(?:export\s+)?([A-Za-z_]\w*)\s*=\s*(.*)$/);
    if (!m || line.trim().startsWith('#')) continue;
    const raw = m[2].trim(), q = raw.match(/^(['"])(.*?)\1/);
    if (process.env[m[1]] === undefined) process.env[m[1]] = q ? q[2] : raw.replace(/\s+#.*$/, '');
  }
}
function normalizeConfig() {
  CONFIG.UUID = CONFIG.UUID || crypto.randomUUID();
  CONFIG.PORT = CONFIG.PORT.replace(/^0+$/, '');
  CONFIG.CERT_HOST = CONFIG.CERT_HOST.replace(/^[a-z]+:\/\//i, '').replace(/[/:].*$/, '');
}
// 把配置持久化到 .env(权限 600)，并把脚本中的 CONFIG 改为只读环境变量
function persistEnv(file) {
  const q = (k, v) => `${k}=${/[\s#'"]/.test(v) ? `"${v}"` : v}`;
  let text = readLog(file);
  for (const [k, v] of Object.entries(CONFIG)) {
    const re = new RegExp(`^\\s*(?:export\\s+)?${k}\\s*=.*$`, 'm');
    text = re.test(text) ? text.replace(re, () => q(k, v)) : `${text}${text && !text.endsWith('\n') ? '\n' : ''}${q(k, v)}\n`;
  }
  try { fs.writeFileSync(file, text, { mode: 0o600 }); fs.chmodSync(file, 0o600); } catch (e) { console.error(`[ENV] Cannot write ${file}: ${e.message}`); }
  rewriteConfigToEnvReads();
}
function rewriteConfigToEnvReads() {
  try {
    const src = fs.readFileSync(SELF, 'utf8');
    const block = src.match(/^const CONFIG = \{\n[\s\S]*?\n\};/m);
    if (!block) return console.error('[ENV] CONFIG block not found, script not rewritten');
    const out = block[0].replace(/^  ([A-Z0-9_]+): .*$/gm, (l, k) => (k in CONFIG ? `  ${k}: ${/_MODE$|^LOG_LEVEL$/.test(k) ? 'mode' : 'env'}('${k}'),` : l));
    fs.writeFileSync(SELF, src.replace(block[0], () => out));
  } catch (e) { console.error(`[ENV] Cannot rewrite script: ${e.message}`); }
}

const toB64 = (d) => Buffer.from(d).toString('base64');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const validPort = (v) => /^\d+$/.test(v) && +v >= 1 && +v <= 65535;
const nonEmpty = (f) => { try { return fs.statSync(f).size > 0; } catch { return false; } };
const urlEncode = (t) => encodeURIComponent(t).replace(/[!'()*]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`);

// HTTPS 请求：跟随重定向；传 file 则写入文件，否则返回 { status, body }
function request(url, { family, timeout = 10000, file, redirects = 5 } = {}) {
  return new Promise((resolve, reject) => {
    const r = https.get(url, { family }, (res) => {
      const { statusCode: status, headers } = res;
      if ([301, 302, 303, 307, 308].includes(status) && headers.location) {
        res.resume();
        return redirects <= 0 ? reject(new Error('too many redirects'))
          : request(new URL(headers.location, url).href, { family, timeout, file, redirects: redirects - 1 }).then(resolve, reject);
      }
      if (file) {
        if (status >= 400) { res.resume(); return reject(new Error(`HTTP ${status}`)); }
        return res.pipe(fs.createWriteStream(file).on('finish', () => resolve({ status })).on('error', reject));
      }
      const chunks = [];
      res.on('data', (c) => chunks.push(c)).on('end', () => resolve({ status, body: Buffer.concat(chunks).toString() })).on('error', reject);
    });
    r.setTimeout(timeout, () => r.destroy(new Error('timeout')));
    r.on('error', reject);
  });
}

// 先写 .part 再改名，失败重试 3 次
async function download(dest, url) {
  let err;
  for (let i = 0; i < 3; i++) {
    try { await request(url, { file: `${dest}.part` }); fs.renameSync(`${dest}.part`, dest); return true; }
    catch (e) { err = e; fs.rmSync(`${dest}.part`, { force: true }); await sleep(1000); }
  }
  console.error(`[DL] Download failed: ${url} (${err?.code ?? ''} ${err?.message ?? 'unknown error'})`);
  return false;
}

// 流式解压 zip：只读中央目录，逐文件解压
async function unzip(zipFile, dir) {
  const root = path.resolve(dir), fd = fs.openSync(zipFile, 'r'), size = fs.fstatSync(fd).size;
  const readAt = (len, pos) => { const b = Buffer.alloc(len); fs.readSync(fd, b, 0, len, pos); return b; };
  try {
    const tail = readAt(Math.min(size, 65557), Math.max(0, size - 65557));
    let end = tail.length - 22;
    while (end >= 0 && tail.readUInt32LE(end) !== 0x06054b50) end--;
    if (end < 0) throw new Error('not a zip file');
    const central = readAt(tail.readUInt32LE(end + 12), tail.readUInt32LE(end + 16));
    for (let i = 0, c = 0; i < tail.readUInt16LE(end + 10); i++) {
      const method = central.readUInt16LE(c + 10), csize = central.readUInt32LE(c + 20);
      const nameLen = central.readUInt16LE(c + 28), offset = central.readUInt32LE(c + 42);
      const name = central.toString('utf8', c + 46, c + 46 + nameLen);
      c += 46 + nameLen + central.readUInt16LE(c + 30) + central.readUInt16LE(c + 32);
      const entry = path.resolve(root, name);
      if (name.endsWith('/') || !entry.startsWith(root + path.sep)) continue;
      fs.mkdirSync(path.dirname(entry), { recursive: true });
      if (!csize) { fs.writeFileSync(entry, ''); continue; }
      const local = readAt(30, offset), start = offset + 30 + local.readUInt16LE(26) + local.readUInt16LE(28);
      await pipeline(fs.createReadStream(zipFile, { start, end: start + csize - 1 }),
        ...(method === 0 ? [] : [zlib.createInflateRaw()]), fs.createWriteStream(entry));
    }
  } finally { fs.closeSync(fd); }
}

// Go 程序内存参数：GOGC 调低；有容器内存限制时设 GOMEMLIMIT
const GO_ENV = (() => {
  const lim = +(readLog('/sys/fs/cgroup/memory.max').trim() || readLog('/sys/fs/cgroup/memory/memory.limit_in_bytes').trim());
  return { GOGC: '50', ...(lim > 0 && lim < 2 ** 40 ? { GOMEMLIMIT: `${Math.floor(lim * 0.6 / 1048576)}MiB` } : {}) };
})();

const children = [];
process.on('exit', () => children.forEach((c) => { try { c.kill(); } catch {} }));
for (const sig of ['SIGINT', 'SIGTERM']) process.on(sig, () => process.exit(0));

async function killPrevious(name, tag) {
  try { cp.execFileSync('pkill', ['-x', name], { stdio: 'ignore' }); } catch { return; }
  console.log(`[${tag}] Stopped previous ${name}`);
  await sleep(1000);
}

function spawnBackground(bin, args, logFile, extraEnv = {}) {
  const fd = fs.openSync(logFile, 'w');
  const child = cp.spawn(bin, args, { env: { ...process.env, ...GO_ENV, ...extraEnv }, stdio: ['ignore', fd, fd] });
  fs.closeSync(fd);
  children.push(child);
  return child;
}

// ========== 协议与模式 ==========
const PROTOCOLS = ['vless', 'vmess', 'trojan', 'shadowsocks'];
const WS_PATH = Object.fromEntries(PROTOCOLS.map((p) => [p, `/${UUID}-${p === 'shadowsocks' ? 'ss' : p}`]));
const SS_PORT = 40004, SS_WS_PORT = 40005;
const abstractSocket = (name) => `@xray-${crypto.createHash('sha1').update(BASE_DIR).digest('hex').slice(0, 8)}-${name}`;
const endpointOf = (p, name, ssPort) => (p === 'shadowsocks' ? { listen: '127.0.0.1', port: ssPort, dest: ssPort } : { listen: abstractSocket(name), dest: abstractSocket(name) });
const internalEndpoint = (p) => endpointOf(p, p, SS_PORT);
const wsInternalEndpoint = (p) => endpointOf(p, `${p}-ws`, SS_WS_PORT);
const FRONT_SOCKET = abstractSocket('front'), WEB_SOCKET = abstractSocket('web');
const DEFAULT_FRONT_PORT = 8000, WG_CLIENT_ADDR = '10.0.0.2/32';
const MODES = { vless: VLESS_MODE, vmess: VMESS_MODE, trojan: TROJAN_MODE, shadowsocks: SHADOWSOCKS_MODE };
const NUMERIC_PORT = {}, FALLBACK = {}, FALLBACK_PARENT = {}, CHAIN = {}, HEAD_PORT = {}, REALITY_PORT = {};
const ENABLED = [], WS_PROTOCOLS = [], CF_PROTOCOLS = [], CHAIN_HEADS = [];
const FRONT_PROTOCOLS = () => [...new Set([...WS_PROTOCOLS, ...CF_PROTOCOLS])];
let HAS_WS = false, HAS_CF = false, QUICK_TUNNEL = false, WS_FRONT_ON = false, CF_FRONT_ON = false;
let SHARE_FRONT = false, FRONT_TLS = false, FRONT_PORT = 0, CF_PORT = 0, XRAY_ON = false;
const ENCODED_NAME = urlEncode(NAME);

// 前置入口的非 ws 请求回落到内置 HTTP 服务
let WEB_DESTINATION = '';
if (PORT && CERT_HOST) {
  WEB_DESTINATION = `${CERT_HOST}:80`;
  if (!/^[A-Za-z0-9.-]+:\d{1,5}$/.test(WEB_DESTINATION)) die(`[WEB] CERT_HOST='${CERT_HOST}' is invalid (expected a domain or an IPv4 address)`);
  console.log(`[WEB] Other paths on the front port are forwarded to ${WEB_DESTINATION}`);
}

const modePort = (name, v, desc) => {
  if (!v) return 0;
  if (!validPort(v)) die(`[MODE] ${name}='${v}' is invalid (expected a port 1-65535, or empty to disable)`);
  console.log(`[MODE] port ${+v}/${desc}`);
  return +v;
};
const HYSTERIA2_PORT = modePort('HYSTERIA2_MODE', HYSTERIA2_MODE, 'udp: hysteria2');
const MIXED_PORT = modePort('MIXED_MODE', MIXED_MODE, 'tcp: mixed (socks5 + http)');
const WIREGUARD_PORT = modePort('WIREGUARD_MODE', WIREGUARD_MODE, 'udp: wireguard');

// 1. 解析各协议的 *_MODE
function parseModes() {
  for (const protocol of PROTOCOLS) {
    const v = `${protocol.toUpperCase()}_MODE`;
    let hasReality = false;
    for (const token of (MODES[protocol] || '').split(',').map((s) => s.trim()).filter(Boolean)) {
      if (token === 'ws' || token === 'cloudflare') {
        const list = token === 'ws' ? WS_PROTOCOLS : CF_PROTOCOLS;
        if (list.includes(protocol)) die(`[MODE] ${v}: '${token}' is given more than once`);
        list.push(protocol);
        if (token === 'ws') HAS_WS = true; else HAS_CF = true;
        continue;
      }
      if (hasReality) die(`[MODE] ${v}: only one Reality entry (a port or a fallback protocol) is allowed`);
      hasReality = true;
      if (/^\d+$/.test(token)) {
        if (!validPort(token)) die(`[MODE] ${v}='${token}': port must be 1-65535`);
        NUMERIC_PORT[protocol] = +token;
      } else if (/^[a-z]+$/.test(token)) {
        if (!PROTOCOLS.includes(token)) die(`[MODE] ${v}='${token}' is not valid`);
        if (token === protocol) die(`[MODE] ${v}='${token}': a protocol cannot fall back to itself`);
        if (!['vless', 'trojan'].includes(protocol)) die(`[MODE] ${v}='${token}': only VLESS and TROJAN can choose a fallback`);
        FALLBACK[protocol] = token;
      } else die(`[MODE] ${v}='${token}' is invalid`);
    }
  }
  QUICK_TUNNEL = HAS_CF && CLOUDFLARE_TUNNEL_TOKEN === 'try';
}

// 2. 整理回落关系为 Reality 链
function buildChains() {
  for (let changed = true; changed;) {
    changed = false;
    for (const [p, t] of Object.entries(FALLBACK)) {
      if (NUMERIC_PORT[t] || FALLBACK[t]) continue;
      console.log(`[MODE] ${p.toUpperCase()}_MODE='${t}': ${t.toUpperCase()} has no Reality port, so this fallback entry is ignored`);
      delete FALLBACK[p];
      changed = true;
    }
  }
  for (const [p, t] of Object.entries(FALLBACK)) {
    if (FALLBACK_PARENT[t]) die(`[MODE] ${t.toUpperCase()} is the fallback of both ${FALLBACK_PARENT[t].toUpperCase()} and ${p.toUpperCase()}, it can only have one`);
    FALLBACK_PARENT[t] = p;
  }
  for (const p of PROTOCOLS) {
    const hasReality = !!(NUMERIC_PORT[p] || FALLBACK[p]);
    if (FRONT_PROTOCOLS().includes(p) || hasReality || FALLBACK_PARENT[p]) ENABLED.push(p);
    if (hasReality && !FALLBACK_PARENT[p]) CHAIN_HEADS.push(p);
  }
  for (const head of CHAIN_HEADS) {
    let tail = head;
    CHAIN[head] = [head];
    while (FALLBACK[tail]) { tail = FALLBACK[tail]; CHAIN[head].push(tail); }
    HEAD_PORT[head] = NUMERIC_PORT[tail];
    for (const p of CHAIN[head]) REALITY_PORT[p] = HEAD_PORT[head];
  }
  XRAY_ON = ENABLED.length > 0 || !!(HYSTERIA2_PORT || MIXED_PORT || WIREGUARD_PORT);
  for (const p of ENABLED) if ((NUMERIC_PORT[p] || FALLBACK[p] || FALLBACK_PARENT[p]) && !REALITY_PORT[p]) die(`[MODE] ${p.toUpperCase()} is part of a fallback loop`);
}

// 3. 前置入口规划
function planFront() {
  WS_FRONT_ON = HAS_WS || (!!PORT && !HAS_CF);
  CF_FRONT_ON = HAS_CF;
  if (WS_FRONT_ON) {
    if (PORT && !validPort(PORT)) die(`[MODE] PORT='${PORT}' is not a valid port`);
    FRONT_PORT = +(PORT || DEFAULT_FRONT_PORT);
    if (PORT && CHAIN_HEADS.some((h) => HEAD_PORT[h] === FRONT_PORT)) SHARE_FRONT = true;
  }
}

// 4. 端口检查
function checkPorts() {
  const ports = CHAIN_HEADS.map((h) => HEAD_PORT[h]);
  if (WS_FRONT_ON && !SHARE_FRONT) ports.push(FRONT_PORT);
  if (CF_FRONT_ON && CF_PORT) ports.push(CF_PORT);
  if (MIXED_PORT) ports.push(MIXED_PORT);
  const dup = ports.find((p, i) => ports.indexOf(p) !== i);
  if (dup !== undefined) die(`[MODE] Port ${dup} is used more than once`);
  const bad = ports.find((p) => p === SS_PORT || p === SS_WS_PORT);
  if (bad !== undefined) die(`[MODE] Port ${bad} conflicts with the internal ports 40004 / 40005 used by Shadowsocks`);
}

// ========== TLS 证书 ==========
const IPV4 = /^\d{1,3}(\.\d{1,3}){3}$/;
let CERT_FILE = '', KEY_FILE = '', TLS_SERVER_NAME = '', TLS_INSECURE = true, TLS_PINNED_CERT_SHA256 = '';

// 自签证书(RSA 2048，10 年)；已有且 30 天内不过期则复用
function generateSelfSignedCert(cn) {
  const dir = path.join(WORK_DIR, '.selfsigned');
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  CERT_FILE = path.join(dir, `${cn}.crt`); KEY_FILE = path.join(dir, `${cn}.key`);
  if (nonEmpty(CERT_FILE) && nonEmpty(KEY_FILE)) {
    try { if (Date.parse(new X509Certificate(fs.readFileSync(CERT_FILE)).validTo) - Date.now() > 30 * 86400e3) return; } catch {}
  }
  cp.execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '3650',
    '-keyout', KEY_FILE, '-out', CERT_FILE, '-subj', `/CN=${cn}`, '-addext', `subjectAltName=DNS:${cn},DNS:localhost`], { stdio: 'ignore' });
  fs.chmodSync(KEY_FILE, 0o600);
}

// 校验证书链：域名匹配、逐级验签、最终落在系统信任根上；返回空串表示可信
function verifyChain(certs, host) {
  if (!certs[0].checkHost(host)) return 'hostname mismatch';
  const roots = (tls.getCACertificates ? tls.getCACertificates('default') : tls.rootCertificates).map((p) => new X509Certificate(p));
  const now = Date.now();
  const valid = (c) => now >= Date.parse(c.validFrom) && now <= Date.parse(c.validTo);
  const signedBy = (c, i) => c.checkIssued(i) && c.verify(i.publicKey);
  let cur = certs[0];
  for (let depth = 0; depth < 8; depth++) {
    if (!valid(cur)) return 'certificate expired or not yet valid';
    if (roots.some((r) => r.fingerprint256 === cur.fingerprint256 || (valid(r) && signedBy(cur, r)))) return '';
    cur = certs.slice(1).find((i) => i !== cur && i.ca && signedBy(cur, i));
    if (!cur) return 'issuer is not trusted';
  }
  return 'chain too long';
}

function trustedCertForHost(host) {
  const certFile = path.join(WORK_DIR, `${host}.crt`), keyFile = path.join(WORK_DIR, `${host}.key`);
  if (!nonEmpty(certFile) || !nonEmpty(keyFile)) return false;
  let certs;
  try {
    certs = (fs.readFileSync(certFile, 'utf8').match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g) || []).map((p) => new X509Certificate(p));
    if (!certs.length || !certs[0].checkPrivateKey(crypto.createPrivateKey(fs.readFileSync(keyFile)))) throw new Error('no matching certificate and key');
  } catch (e) { console.error(`[TLS] Cannot read ${certFile} / ${keyFile}: ${e.message}`); return false; }
  const reason = verifyChain(certs, host);
  if (reason) { console.error(`[TLS] ${certFile} is not trusted for ${host}: ${reason}`); return false; }
  CERT_FILE = certFile; KEY_FILE = keyFile;
  return true;
}

function setupTls() {
  TLS_SERVER_NAME = CERT_HOST || 'www.nazhumi.com';
  TLS_INSECURE = !(CERT_HOST && !IPV4.test(CERT_HOST) && trustedCertForHost(CERT_HOST));
  if (TLS_INSECURE) {
    console.error(`[TLS] No trusted certificate (put one at ${WORK_DIR}/<CERT_HOST>.crt and .key), using self-signed certificate`);
    generateSelfSignedCert(TLS_SERVER_NAME);
    TLS_PINNED_CERT_SHA256 = new X509Certificate(fs.readFileSync(CERT_FILE)).fingerprint256.replace(/:/g, '').toLowerCase();
  }
  console.log(`[TLS] Server name: ${TLS_SERVER_NAME}, insecure: ${TLS_INSECURE ? 1 : 0}, cert: ${CERT_FILE}`);
}

// ========== 密钥(由 UUID 派生，同一 UUID 永远得到同一组密钥) ==========
function deriveKey(label, encoding) {
  const priv = crypto.createHash('sha256').update(`${label}:${UUID}`).digest();
  priv[0] &= 248; priv[31] = (priv[31] & 127) | 64;
  const pub = crypto.createPublicKey(crypto.createPrivateKey({
    key: Buffer.concat([Buffer.from('302e020100300506032b656e04220420', 'hex'), priv]), format: 'der', type: 'pkcs8',
  })).export({ type: 'spki', format: 'der' }).subarray(-32);
  return [priv.toString(encoding), Buffer.from(pub).toString(encoding)];
}

// ========== 链接地址 ==========
let PUBLIC_ADDRESS = '';
const TRACE_URL = 'https://one.one.one.one/cdn-cgi/trace';

async function resolvePublicAddress() {
  if (IPV4.test(CERT_HOST)) PUBLIC_ADDRESS = CERT_HOST;
  else {
    const trace = await request(TRACE_URL, { family: 4, timeout: 5000 }).catch(() => null);
    PUBLIC_ADDRESS = ((trace && trace.body.match(/^ip=(.*)$/m)) || [, ''])[1].trim();
    if (CERT_HOST && PUBLIC_ADDRESS) {
      const ips = await dns.promises.lookup(CERT_HOST, { family: 4, all: true }).then((l) => l.map((e) => e.address)).catch(() => []);
      if (ips.includes(PUBLIC_ADDRESS)) { console.log(`[NET] ${CERT_HOST} points to this server, using it instead of the IP`); PUBLIC_ADDRESS = CERT_HOST; }
    }
  }
  if (!PUBLIC_ADDRESS) console.error('[NET] Cannot determine the public address, links will be invalid (set CERT_HOST)');
  console.log(`[NET] Address in links: ${PUBLIC_ADDRESS}`);
}

// ========== Xray 配置 ==========
let REALITY_PRIVATE_KEY = '', REALITY_PUBLIC_KEY = '', REALITY_SHORT_ID = '', VLESS_FLOW = '', IPV6_AVAILABLE = false;
let WG_SERVER_PRIV = '', WG_SERVER_PUB = '', WG_CLIENT_PRIV = '', WG_CLIENT_PUB = '';
const SNIFFING = { enabled: true, destOverride: ['http', 'tls', 'quic'], routeOnly: true };

const streamTcp = () => ({ network: 'tcp', security: 'none' });
const streamWs = (p) => ({ network: 'ws', security: 'none', wsSettings: { path: p } });
const streamReality = (dest = 'www.iij.ad.jp:443', sni = 'www.iij.ad.jp') => ({
  network: 'tcp', security: 'reality',
  realitySettings: { show: false, dest, xver: 0, serverNames: [sni], privateKey: REALITY_PRIVATE_KEY, shortIds: [REALITY_SHORT_ID] },
});
const streamTls = (network, alpn, extra = {}) => ({
  network, security: 'tls',
  tlsSettings: { serverName: TLS_SERVER_NAME, alpn: [alpn], certificates: [{ certificateFile: CERT_FILE, keyFile: KEY_FILE }] },
  ...extra,
});
const inbound = (tag, listen, port, protocol, settings, stream) => ({ tag, listen, port, protocol, settings, streamSettings: stream, sniffing: SNIFFING });

function protocolSettings(p, fallbacks, flow) {
  const fb = fallbacks ? { fallbacks } : {};
  switch (p) {
    case 'vless': return { clients: [{ id: UUID, email: UUID, ...(flow ? { flow } : {}) }], decryption: 'none', ...fb };
    case 'vmess': return { clients: [{ id: UUID, email: UUID }] };
    case 'trojan': return { clients: [{ password: UUID, email: UUID }], ...fb };
    case 'shadowsocks': return { method: 'aes-256-gcm', password: UUID, network: 'tcp' };
  }
}

function buildConfig() {
  const inbounds = [];
  for (const p of FRONT_PROTOCOLS()) {
    const ep = wsInternalEndpoint(p);
    inbounds.push(inbound(`${p}-ws-in`, ep.listen, ep.port, p, protocolSettings(p), streamWs(WS_PATH[p])));
  }
  const frontFallbacks = (protocols) => [
    ...protocols.map((p) => ({ path: WS_PATH[p], dest: wsInternalEndpoint(p).dest, xver: 0 })),
    { dest: WEB_SOCKET, xver: 0 },
  ];
  if (WS_FRONT_ON) {
    const [listen, port] = SHARE_FRONT ? [FRONT_SOCKET, undefined] : ['::', FRONT_PORT];
    inbounds.push(inbound('front-in', listen, port, 'vless', protocolSettings('vless', frontFallbacks(WS_PROTOCOLS)), FRONT_TLS ? streamTls('tcp', 'http/1.1') : streamTcp()));
  }
  if (CF_FRONT_ON) inbounds.push(inbound('cf-front-in', '::', CF_PORT, 'vless', protocolSettings('vless', frontFallbacks(CF_PROTOCOLS)), streamTcp()));
  for (const head of CHAIN_HEADS) {
    for (const p of CHAIN[head]) {
      const fallbacks = FALLBACK[p] ? [{ dest: internalEndpoint(FALLBACK[p]).dest, xver: 0 }] : undefined;
      if (p !== head) {
        const ep = internalEndpoint(p);
        inbounds.push(inbound(`${p}-in`, ep.listen, ep.port, p, protocolSettings(p, fallbacks), streamTcp()));
        continue;
      }
      const stream = SHARE_FRONT && HEAD_PORT[head] === FRONT_PORT ? streamReality(FRONT_SOCKET, TLS_SERVER_NAME) : streamReality();
      inbounds.push(inbound(`${p}-in`, '::', HEAD_PORT[head], p, protocolSettings(p, fallbacks, p === 'vless' ? VLESS_FLOW : ''), stream));
    }
  }
  if (HYSTERIA2_PORT) inbounds.push(inbound('hysteria2-in', '::', HYSTERIA2_PORT, 'hysteria', { version: 2, clients: [{ auth: UUID, email: UUID }] }, streamTls('hysteria', 'h3', { hysteriaSettings: { version: 2 } })));
  if (MIXED_PORT) inbounds.push(inbound('mixed-in', '::', MIXED_PORT, 'socks', { auth: 'password', accounts: [{ user: UUID, pass: UUID }], udp: false }, streamTcp()));
  if (WIREGUARD_PORT) inbounds.push(inbound('wireguard-in', '::', WIREGUARD_PORT, 'wireguard', { secretKey: WG_SERVER_PRIV, peers: [{ publicKey: WG_CLIENT_PUB, allowedIPs: [WG_CLIENT_ADDR] }], mtu: 1420 }));

  return {
    log: { loglevel: LOG_LEVEL },
    dns: { servers: ['https+local://1.1.1.1/dns-query'], queryStrategy: 'UseIPv4' },
    inbounds,
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
let SS_USERINFO = '', CF_HOSTNAME = '';

function realityLink(p, port, name) {
  const sni = SHARE_FRONT && port === FRONT_PORT ? TLS_SERVER_NAME : 'www.iij.ad.jp';
  const prefix = p === 'vless' ? `encryption=none${VLESS_FLOW ? `&flow=${VLESS_FLOW}` : ''}&` : p === 'vmess' ? 'encryption=auto&' : '';
  const q = `security=reality&sni=${sni}&fp=chrome&pbk=${REALITY_PUBLIC_KEY}&type=tcp&sid=${REALITY_SHORT_ID}`;
  const userinfo = p === 'shadowsocks' ? SS_USERINFO : UUID;
  return `${p === 'shadowsocks' ? 'ss' : p}://${userinfo}@${PUBLIC_ADDRESS}:${port}?${prefix}${q}#${urlEncode(name)}`;
}

function wsParams(mode) {
  if (mode === 'cloudflare') return { mode, address: CLOUDFLARE_IP || CF_HOSTNAME, port: 443, host: CF_HOSTNAME, insecure: 0, pinned: '', extra: null, query: '' };
  const insecure = TLS_INSECURE ? 1 : 0;
  return {
    mode, address: PUBLIC_ADDRESS, port: FRONT_PORT, host: TLS_SERVER_NAME, insecure, pinned: TLS_PINNED_CERT_SHA256,
    extra: { allowInsecure: insecure, verify_cert: !TLS_INSECURE },
    query: TLS_INSECURE ? `&allowInsecure=1&pcs=${TLS_PINNED_CERT_SHA256}` : '',
  };
}

function wsLink(p, w, name) {
  const wsPath = WS_PATH[p], encName = urlEncode(name);
  const q = `sni=${w.host}&fp=chrome&type=ws&host=${w.host}&path=${wsPath.replace(/\//g, '%2F')}${w.query}#${encName}`;
  switch (p) {
    case 'vless': return `vless://${UUID}@${w.address}:${w.port}?encryption=none&security=tls&${q}`;
    case 'trojan': return `trojan://${UUID}@${w.address}:${w.port}?security=tls&${q}`;
    case 'vmess': return `vmess://${toB64(JSON.stringify({
      v: '2', ps: name, add: w.address, port: String(w.port), id: UUID, aid: '0', scy: 'none', net: 'ws', type: 'none',
      host: w.host, path: wsPath + (w.mode === 'cloudflare' ? '?ed=2560' : ''), tls: 'tls', sni: w.host, alpn: '', fp: '',
      insecure: String(w.insecure), ...(w.extra || {}), vcn: '', pcs: w.pinned,
    }))}`;
    case 'shadowsocks': {
      if (w.mode === 'ws' && TLS_INSECURE) {
        console.error('[MODE] ws mode: Shadowsocks (v2ray-plugin) needs a trusted certificate, no SS link generated');
        return '';
      }
      const plugin = `v2ray-plugin;tls;host=${w.host};path=${wsPath};mux=0`.replace(/;/g, '%3B').replace(/=/g, '%3D').replace(/\//g, '%2F');
      return `ss://${SS_USERINFO}@${w.address}:${w.port}/?plugin=${plugin}#${encName}`;
    }
  }
}

const realityNodes = () => ENABLED.filter((p) => REALITY_PORT[p]).map((p) => realityLink(p, REALITY_PORT[p], NAME));
const wsNodes = (w) => ENABLED.filter((p) => WS_PROTOCOLS.includes(p))
  .map((p) => wsLink(p, w, (REALITY_PORT[p] || CF_PROTOCOLS.includes(p)) ? `${NAME}-ws` : NAME));
const cloudflareNodes = (w) => ENABLED.filter((p) => CF_PROTOCOLS.includes(p)).map((p) => wsLink(p, w, NAME));
const hysteria2Link = () => `hysteria2://${UUID}@${PUBLIC_ADDRESS}:${HYSTERIA2_PORT}/?sni=${TLS_SERVER_NAME}${TLS_INSECURE ? '&insecure=1' : ''}#${ENCODED_NAME}`;
const mixedLinks = () => ['socks5', 'http'].map((s) => `${s}://${UUID}:${UUID}@${PUBLIC_ADDRESS}:${MIXED_PORT}#${ENCODED_NAME}`).join('\n');
const wireguardLink = () => `wireguard://${urlEncode(WG_CLIENT_PRIV)}@${PUBLIC_ADDRESS}:${WIREGUARD_PORT}?publickey=${urlEncode(WG_SERVER_PUB)}&address=${urlEncode(WG_CLIENT_ADDR)}&mtu=1420#${ENCODED_NAME}`;
const wireguardConfig = () => `[Interface]\nPrivateKey = ${WG_CLIENT_PRIV}\nAddress = ${WG_CLIENT_ADDR}\nDNS = 1.1.1.1\nMTU = 1420\n\n[Peer]\nPublicKey = ${WG_SERVER_PUB}\nEndpoint = ${PUBLIC_ADDRESS}:${WIREGUARD_PORT}\nAllowedIPs = 0.0.0.0/0, ::/0\nPersistentKeepalive = 25\n`;

// ========== 内置 HTTP 服务(订阅 + 回落) ==========
function startWeb(subBody) {
  const [dHost, dPort] = WEB_DESTINATION.split(':');
  http.createServer((q, s) => {
    const pathname = q.url.split('?')[0];
    console.log(`[WEB] ${q.method} ${pathname === `/${UUID}` ? '/UUID' : pathname}`);
    if ((q.method === 'GET' || q.method === 'HEAD') && pathname === `/${UUID}`) {
      s.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store' });
      return s.end(q.method === 'HEAD' ? undefined : subBody);
    }
    if (!WEB_DESTINATION) { s.writeHead(404, { 'Content-Type': 'text/plain' }); return s.end('Not Found'); }
    const up = http.request({ host: dHost, port: +dPort, path: q.url, method: q.method, headers: q.headers }, (ur) => { s.writeHead(ur.statusCode, ur.headers); ur.pipe(s); });
    up.on('error', () => { s.writeHead(502); s.end(); });
    q.pipe(up);
  }).on('error', (e) => console.error(`[WEB] HTTP service failed: ${e.message}`)).listen(`\0${WEB_SOCKET.slice(1)}`);
}

// ========== 外部程序 ==========
async function fetchBinary(name, url) {
  const bin = path.join(WORK_DIR, name);
  if (!await download(bin, url)) process.exit(1);
  fs.chmodSync(bin, 0o755);
  return bin;
}

async function startKomari() {
  const name = `svc-k${h4}`;
  await killPrevious(name, 'KOMARI');
  const bin = await fetchBinary(name, `https://github.com/komari-monitor/komari-agent/releases/latest/download/komari-agent-linux-${ARCH}`);
  const agentEnv = { AGENT_ENDPOINT: KOMARI_ENDPOINT, AGENT_TOKEN: KOMARI_TOKEN };
  if (XRAY_ON) {
    spawnBackground(bin, [], QUIET ? '/dev/null' : path.join(WORK_DIR, `${name}.log`), agentEnv);
    return console.log(`[KOMARI] Agent started, reporting to ${KOMARI_ENDPOINT}`);
  }
  console.log(`[KOMARI] No proxy protocol enabled, running the agent only, reporting to ${KOMARI_ENDPOINT}`);
  const child = cp.spawn(bin, [], { env: { ...process.env, ...GO_ENV, ...agentEnv }, stdio: STDIO });
  children.push(child);
  child.on('exit', (code) => process.exit(code ?? 1));
  await new Promise(() => {});
}

// 从 cloudflared 日志取第一条有具体域名、Service 为 http://localhost:端口 的 ingress 规则
function parseIngress(text) {
  const m = text.split('\n').filter((l) => l.includes('Updated to new configuration')).pop()?.match(/config="(.*)" version=/);
  if (!m) return null;
  let config;
  try { config = JSON.parse(m[1].replace(/\\"/g, '"')); } catch { return null; }
  for (const rule of config.ingress || []) {
    const sm = rule.hostname && !rule.hostname.includes('*') && /^http:\/\/(?:localhost|127\.0\.0\.1):(\d+)$/.exec(rule.service || '');
    if (sm) return { hostname: rule.hostname, port: sm[1] };
  }
  return null;
}

async function startCloudflared() {
  const name = `svc-c${h4}`;
  await killPrevious(name, 'CF');
  const bin = await fetchBinary(name, `https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-${ARCH}`);
  const logFile = path.join(WORK_DIR, `${name}.log`);
  const fail = (msg) => { console.error(`[CF] ${msg}`); process.exit(1); };
  cp.spawnSync(bin, ['--version'], { stdio: STDIO });

  if (QUICK_TUNNEL) {
    CF_PORT = DEFAULT_FRONT_PORT;
    checkPorts();
    spawnBackground(bin, ['--no-autoupdate', 'tunnel', '--url', `http://localhost:${CF_PORT}`], logFile);
    for (let i = 0; i < 30 && !CF_HOSTNAME; i++) {
      CF_HOSTNAME = [...readLog(logFile).matchAll(/https:\/\/([a-z0-9-]+\.trycloudflare\.com)/g)].map((m) => m[1]).find((h) => !h.startsWith('api.')) || '';
      if (!CF_HOSTNAME) await sleep(1000);
    }
    if (!CF_HOSTNAME) fail(`Cannot find the trycloudflare.com hostname in ${logFile}, exiting`);
    console.log(`[CF] Quick tunnel hostname: ${CF_HOSTNAME} (service port=${CF_PORT})`);
  } else {
    spawnBackground(bin, ['--no-autoupdate', 'tunnel', 'run'], logFile, { TUNNEL_TOKEN: CLOUDFLARE_TUNNEL_TOKEN });
    for (let i = 0; i < 30 && !readLog(logFile).includes('Updated to new configuration'); i++) await sleep(1000);
    const rule = parseIngress(readLog(logFile));
    if (!rule || !validPort(rule.port)) fail(`Cannot read hostname / port from ${logFile} (needs a Public hostname without * and a Service like http://localhost:PORT), exiting`);
    CF_HOSTNAME = rule.hostname;
    CF_PORT = +rule.port;
    checkPorts();
    console.log(`[CF] From cloudflared log: hostname=${CF_HOSTNAME}, tunnel service port=${CF_PORT}`);
  }
  if (QUIET) fs.rmSync(logFile, { force: true });
}

// ========== 主流程 ==========
async function main() {
  parseModes();
  buildChains();
  planFront();
  FRONT_TLS = HAS_WS || SHARE_FRONT;
  checkPorts();

  if (ENABLED.length) console.log(`[MODE] enabled=${ENABLED.join(' ')}`);
  if (WS_FRONT_ON) console.log(`[MODE] port ${FRONT_PORT}: ws (${WS_PROTOCOLS.join(' ') || 'subscription only'})${SHARE_FRONT ? ' shared with reality' : ''}`);
  if (CF_FRONT_ON) console.log(`[MODE] cloudflare: ${CF_PROTOCOLS.join(' ')} (tunnel port decided by cloudflared log)`);
  for (const head of CHAIN_HEADS) console.log(`[MODE] port ${HEAD_PORT[head]}: reality (${CHAIN[head].join(' -> ')})`);
  VLESS_FLOW = CHAIN_HEADS.includes('vless') ? 'xtls-rprx-vision' : '';

  const KOMARI_ON = !!(KOMARI_ENDPOINT && KOMARI_TOKEN);
  if (!XRAY_ON && !KOMARI_ON) die('[MODE] Nothing to run: set a protocol *_MODE / HYSTERIA2_MODE / MIXED_MODE / WIREGUARD_MODE, or KOMARI_ENDPOINT + KOMARI_TOKEN');
  if (KOMARI_ON) await startKomari();

  if (CHAIN_HEADS.length) {
    [REALITY_PRIVATE_KEY, REALITY_PUBLIC_KEY] = deriveKey('reality', 'base64url');
    REALITY_SHORT_ID = crypto.createHash('sha256').update(`reality-short-id:${UUID}`).digest('hex').slice(0, 8);
    console.log(`[REALITY] Private key: ${REALITY_PRIVATE_KEY}\n[REALITY] Public key: ${REALITY_PUBLIC_KEY}\n[REALITY] Short ID: ${REALITY_SHORT_ID}`);
  }
  if (WIREGUARD_PORT) {
    [WG_SERVER_PRIV, WG_SERVER_PUB] = deriveKey('wg-server', 'base64');
    [WG_CLIENT_PRIV, WG_CLIENT_PUB] = deriveKey('wg-client', 'base64');
  }
  SS_USERINFO = Buffer.from(`aes-256-gcm:${UUID}`).toString('base64url');

  if (WS_FRONT_ON || CHAIN_HEADS.length || HYSTERIA2_PORT || MIXED_PORT || WIREGUARD_PORT) await resolvePublicAddress();
  IPV6_AVAILABLE = await request(TRACE_URL, { family: 6, timeout: 5000 }).then(() => true, () => false);
  console.log(IPV6_AVAILABLE ? '[NET] IPv6 egress: available' : '[NET] IPv6 egress: unavailable, blocking IPv6 destinations');
  if (FRONT_TLS || HYSTERIA2_PORT) setupTls();
  if (HAS_CF) {
    if (!CLOUDFLARE_TUNNEL_TOKEN) die('[CF] cloudflare mode needs CLOUDFLARE_TUNNEL_TOKEN (a tunnel token, or try for a quick tunnel)');
    await startCloudflared();
  }

  // ---- Xray ----
  const xrayBin = path.join(WORK_DIR, `xray-${h4}`), extracted = path.join(WORK_DIR, 'xray');
  const configFile = path.join(WORK_DIR, 'config.json'), zipFile = path.join(WORK_DIR, 'xray.zip');
  await killPrevious(`xray-${h4}`, 'XRAY');
  if (!await download(zipFile, `https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-${ARCH === 'amd64' ? '64' : 'arm64-v8a'}.zip`)) process.exit(1);
  await unzip(zipFile, WORK_DIR);
  fs.rmSync(zipFile, { force: true });
  try { fs.renameSync(extracted, xrayBin); } catch (e) { console.error(`[XRAY] Cannot rename binary: ${e.message}`); }
  if (!nonEmpty(xrayBin)) { console.error(`[XRAY] Binary not found after extraction: ${xrayBin}`); process.exit(1); }
  fs.chmodSync(xrayBin, 0o755);
  const xrayEnv = { ...process.env, ...GO_ENV, XRAY_LOCATION_ASSET: WORK_DIR };
  const runXray = (args) => cp.spawnSync(xrayBin, args, { stdio: STDIO, env: xrayEnv });
  runXray(['version']);

  // 先以 600 权限写入(含 UUID 和 Reality 私钥)，再测试配置
  fs.writeFileSync(configFile, `${JSON.stringify(buildConfig(), null, 2)}\n`, { mode: 0o600 });
  fs.chmodSync(configFile, 0o600);
  if (runXray(['run', '-test', '-c', configFile]).status !== 0) { console.error('[XRAY] Config test failed, aborting'); process.exit(1); }

  // ---- 订阅输出 ----
  const nodes = [
    ...realityNodes(),
    ...(HAS_WS ? wsNodes(wsParams('ws')) : []),
    ...(HAS_CF && CF_HOSTNAME ? cloudflareNodes(wsParams('cloudflare')) : []),
    HYSTERIA2_PORT && hysteria2Link(),
    WIREGUARD_PORT && wireguardLink(),
    MIXED_PORT && mixedLinks(),
  ];
  const allNodes = nodes.filter(Boolean).map((n) => `${n}\n`).join('');
  console.log(`\n=== Nodes ===\n${allNodes}\n=== Subscription (base64) ===\n${toB64(allNodes)}\n`);
  if (WIREGUARD_PORT) console.log(`\n=== WireGuard config (wg-quick) ===\n${wireguardConfig()}`);
  if (WS_FRONT_ON || CF_FRONT_ON) {
    startWeb(toB64(allNodes));
    const bases = [
      ...(CF_FRONT_ON && CF_HOSTNAME ? [`https://${CF_HOSTNAME}`] : []),
      ...(WS_FRONT_ON ? [`${FRONT_TLS ? 'https' : 'http'}://${PUBLIC_ADDRESS}:${FRONT_PORT}`] : []),
    ];
    if (bases.length) console.log(`\n=== Subscription URL ===\n${bases.map((b) => `${b}/${UUID}`).join('\n')}${FRONT_TLS && TLS_INSECURE ? '\n(自签证书：客户端需要允许不校验证书)' : ''}\n`);
  }

  // ---- systemd 服务文件 ----
  const svc = `cache-${uuidHash.slice(0, 6)}`, serviceFile = path.join(WORK_DIR, `${svc}.service`);
  fs.writeFileSync(serviceFile, `[Unit]\nDescription=${svc}\nAfter=network.target\n\n[Service]\nType=simple\nRestart=always\nRestartSec=5\nWorkingDirectory=${WORK_DIR}\nExecStart=${process.execPath} ${SELF}\nKillMode=mixed\nKillSignal=SIGTERM\n\n[Install]\nWantedBy=multi-user.target\n`);
  console.log(`\n=== systemd service (${svc}) ===\ncp ${serviceFile} /etc/systemd/system/${svc}.service\nsystemctl daemon-reload && systemctl enable --now ${svc}`);

  try { req('v8').setFlagsFromString('--expose-gc'); req('vm').runInNewContext('gc')(); } catch {}
  const xrayProcess = cp.spawn(xrayBin, ['run', '-c', configFile], { stdio: STDIO, env: xrayEnv });
  children.push(xrayProcess);
  xrayProcess.on('exit', (code) => process.exit(code ?? 1));
}

main().catch((e) => { console.error(e); process.exit(1); });
