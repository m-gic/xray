#!/usr/bin/env node
'use strict';
// 纯 Node.js(>=16)，仅内置模块。每个 *_MODE 可逗号分隔：一个前置模式 ws/cloudflare + 一个 Reality 项(端口或回落协议名)
const req = (m) => (typeof require === 'function' ? require(m) : process.getBuiltinModule(`node:${m}`));
const [crypto, fs, path, cp, https, http, zlib, dns, tls] = ['crypto', 'fs', 'path', 'child_process', 'https', 'http', 'zlib', 'dns', 'tls'].map(req);
const { X509Certificate } = crypto;
const SELF = path.resolve(process.argv[1]), BASE_DIR = path.dirname(SELF);

// ========== 用户配置 ==========
// 优先级：真实环境变量 > 同目录 .env > 默认值。变量"未设置"才用默认值，设成空就是关闭
loadEnv(path.join(BASE_DIR, '.env'));
const env = (k, d = '') => (process.env[k] ?? d).trim();
const mode = (k, d = '') => env(k, d).toLowerCase();
const CONFIG = {
  NAME: env('NAME', ''),
  UUID: env('UUID') || crypto.randomUUID(),
  CLOUDFLARE_TUNNEL_TOKEN: env('CLOUDFLARE_TUNNEL_TOKEN'),
  CLOUDFLARE_IP: env('CLOUDFLARE_IP', 'visa.cn'),
  PORT: env('PORT').replace(/^0+$/, ''),
  VLESS_MODE: mode('VLESS_MODE', 'trojan'),
  VMESS_MODE: mode('VMESS_MODE', ''),
  TROJAN_MODE: mode('TROJAN_MODE', 'vmess'),
  SHADOWSOCKS_MODE: mode('SHADOWSOCKS_MODE'),
  HYSTERIA2_MODE: env('HYSTERIA2_MODE', ''),
  MIXED_MODE: env('MIXED_MODE'),
  WIREGUARD_MODE: env('WIREGUARD_MODE'),
  CERT_HOST: env('CERT_HOST', '').replace(/^[a-z]+:\/\//i, '').replace(/[/:].*$/, ''),
  WORK_DIR: env('WORK_DIR'), // 留空时由 NAME + UUID 自动派生看起来像系统缓存的路径
  KOMARI_ENDPOINT: env('KOMARI_ENDPOINT', ''),
  KOMARI_TOKEN: env('KOMARI_TOKEN', ''),
  LOG_LEVEL: mode('LOG_LEVEL', 'warning'), // none / error / warning / info / debug
};
const { NAME, UUID, CLOUDFLARE_TUNNEL_TOKEN, CLOUDFLARE_IP, PORT, VLESS_MODE, VMESS_MODE, TROJAN_MODE, SHADOWSOCKS_MODE,
  HYSTERIA2_MODE, MIXED_MODE, WIREGUARD_MODE, CERT_HOST, KOMARI_ENDPOINT, KOMARI_TOKEN, LOG_LEVEL } = CONFIG;
// Xray 进程名：只保留字母数字 . _ -，最长 15 个字符；为空则用 xray
const PROCESS_NAME = NAME.replace(/[^A-Za-z0-9._-]/g, '').slice(0, 15) || 'xray';

// 由 NAME + UUID 派生：目录名如 .fontcache2a3f，服务名如 mynode-2a3f1b
const nameSlug = NAME.replace(/[^a-z0-9]/gi, '').toLowerCase().slice(0, 8) || 'cache';
const uuidHash = crypto.createHash('sha256').update(UUID).digest('hex');
const CACHE_DIR_NAME = `.${nameSlug}${uuidHash.slice(0, 4)}`;
const SERVICE_NAME = `${nameSlug}-${uuidHash.slice(0, 6)}`;

console.log('[ENV]', Object.entries(CONFIG).filter(([, v]) => v).map(([k, v]) => `${k}=${/UUID|TOKEN/.test(k) ? `${v.slice(0, 4)}***` : v}`).join(' '));

// WORK_DIR 优先级：环境变量指定 > /var/lib/<派生名> > /tmp/<派生名>
let WORK_DIR = '';
for (const dir of new Set(CONFIG.WORK_DIR ? [path.resolve(BASE_DIR, CONFIG.WORK_DIR), `/var/lib/${CACHE_DIR_NAME}`, `/tmp/${CACHE_DIR_NAME}`] : [`/var/lib/${CACHE_DIR_NAME}`, `/tmp/${CACHE_DIR_NAME}`])) {
  try {
    fs.mkdirSync(dir, { recursive: true });
    fs.accessSync(dir, fs.constants.R_OK | fs.constants.W_OK);
    WORK_DIR = dir;
    break;
  } catch (e) { console.error(`[DIR] Cannot access ${dir}: ${e.message}`); }
}
if (!WORK_DIR) process.exit(1);
console.log(`[DIR] Work directory: ${WORK_DIR}`);

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

// 把当前 UUID 写回脚本本身：下次运行直接沿用
try {
  fs.writeFileSync(SELF, fs.readFileSync(SELF, 'utf8').replace(/^ {2}UUID: .*$/m, () => `  UUID: env('UUID') || crypto.randomUUID(),`.replace("env('UUID')", `env('UUID', '${UUID}')`)));
} catch (e) { console.error(`[UUID] Cannot persist UUID to script: ${e.message}`); }

process.chdir(WORK_DIR);
const ARCH = { x64: 'amd64', arm64: 'arm64' }[process.arch];
if (!ARCH) { console.error(`[ARCH] Unsupported architecture: ${process.arch}`); process.exit(1); }

// ========== 通用函数 ==========
const toB64 = (d) => Buffer.from(d).toString('base64');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const validPort = (v) => /^[0-9]+$/.test(v) && +v >= 1 && +v <= 65535;
const die = (msg) => { console.error(`[MODE] ${msg}`); process.exit(1); };
const nonEmpty = (f) => { try { return fs.statSync(f).size > 0; } catch { return false; } };
const urlEncode = (t) => encodeURIComponent(t).replace(/[!'()*]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`);

// HTTPS 请求：跟随重定向；file 非空时写入文件，否则返回 { status, body }
function request(url, { family, timeout = 10000, file = null, redirects = 5 } = {}) {
  return new Promise((resolve, reject) => {
    const r = https.get(url, { family }, (res) => {
      const { statusCode: status, headers } = res;
      if ([301, 302, 303, 307, 308].includes(status) && headers.location) {
        res.resume();
        if (redirects <= 0) return reject(new Error('too many redirects'));
        return request(new URL(headers.location, url).href, { family, timeout, file, redirects: redirects - 1 }).then(resolve, reject);
      }
      if (!file) {
        const chunks = [];
        return res.on('data', (c) => chunks.push(c)).on('end', () => resolve({ status, body: Buffer.concat(chunks).toString() })).on('error', reject);
      }
      if (status >= 400) { res.resume(); return reject(new Error(`HTTP ${status}`)); }
      res.pipe(fs.createWriteStream(file).on('finish', () => resolve({ status })).on('error', reject));
    });
    r.setTimeout(timeout, () => r.destroy(new Error('timeout')));
    r.on('error', reject);
  });
}

// 先写 .part 再改名，失败返回 false
async function download(dest, url) {
  let err;
  for (let i = 0; i < 3; i++) {
    try { await request(url, { file: `${dest}.part` }); fs.renameSync(`${dest}.part`, dest); return true; } catch (e) { err = e; fs.rmSync(`${dest}.part`, { force: true }); await sleep(1000); }
  }
  console.error(`[DL] Download failed: ${url} (${[err?.code, err?.message].filter(Boolean).join(' ') || 'unknown error'})`);
  return false;
}

// 流式解压 zip：只读中央目录，逐文件边读边解压边写
async function unzip(zipFile, directory) {
  const { pipeline } = req('stream').promises, root = path.resolve(directory);
  const fd = fs.openSync(zipFile, 'r'), size = fs.fstatSync(fd).size;
  const readAt = (len, pos) => { const b = Buffer.alloc(len); fs.readSync(fd, b, 0, len, pos); return b; };
  const tail = readAt(Math.min(size, 65557), Math.max(0, size - 65557));
  let end = tail.length - 22;
  while (end >= 0 && tail.readUInt32LE(end) !== 0x06054b50) end--;
  if (end < 0) throw new Error('not a zip file');
  const central = readAt(tail.readUInt32LE(end + 12), tail.readUInt32LE(end + 16));
  try {
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
      const src = fs.createReadStream(zipFile, { start, end: start + csize - 1 }), out = fs.createWriteStream(entry);
      await (method === 0 ? pipeline(src, out) : pipeline(src, zlib.createInflateRaw(), out));
    }
  } finally { fs.closeSync(fd); }
}

// Go 程序内存参数：GOGC 调低；有容器内存限制时设 GOMEMLIMIT 软上限
const GO_ENV = (() => {
  const lim = +(readLog('/sys/fs/cgroup/memory.max').trim() || readLog('/sys/fs/cgroup/memory/memory.limit_in_bytes').trim());
  return { GOGC: '50', ...(lim > 0 && lim < 2 ** 40 ? { GOMEMLIMIT: `${Math.floor(lim * 0.6 / 1048576)}MiB` } : {}) };
})();

// 子进程：脚本退出时一并结束
const children = [];
process.on('exit', () => children.forEach((c) => { try { c.kill(); } catch { /* 已退出 */ } }));
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
const WS_PATH = { vless: `/${UUID}-vless`, vmess: `/${UUID}-vmess`, trojan: `/${UUID}-trojan`, shadowsocks: `/${UUID}-ss` };
// 内部连接用 abstract unix socket；Shadowsocks 入站不支持 unix socket，改用本机端口 40004 / 40005
const SS_PORT = 40004, SS_WS_PORT = 40005;
const abstractSocket = (name) => `@xray-${crypto.createHash('sha1').update(BASE_DIR).digest('hex').slice(0, 8)}-${name}`;
const endpointOf = (p, name, ssPort) => (p === 'shadowsocks' ? { listen: '127.0.0.1', port: ssPort, dest: ssPort } : { listen: abstractSocket(name), dest: abstractSocket(name) });
const internalEndpoint = (p) => endpointOf(p, p, SS_PORT);
const wsInternalEndpoint = (p) => endpointOf(p, `${p}-ws`, SS_WS_PORT);
const FRONT_SOCKET = abstractSocket('front'), WEB_SOCKET = abstractSocket('web');
const DEFAULT_FRONT_PORT = 8000, WG_CLIENT_ADDR = '10.0.0.2/32';
const MODES = { vless: VLESS_MODE, vmess: VMESS_MODE, trojan: TROJAN_MODE, shadowsocks: SHADOWSOCKS_MODE };
const NUMERIC_PORT = {}, FALLBACK = {}, FALLBACK_PARENT = {};
const CHAIN = {}, HEAD_PORT = {}, REALITY_PORT = {};
const ENABLED = [], WS_PROTOCOLS = [], CHAIN_HEADS = [];
let ACTIVE_MODE = '', QUICK_TUNNEL = false, FRONT_ON = false, SHARE_FRONT = false, FRONT_TLS = false, FRONT_PORT = 0, XRAY_ON = false;
const ENCODED_NAME = urlEncode(NAME);

// 前置入口的非 ws 请求回落到内置 HTTP 服务：/UUID 返回订阅，其它路径转给 CERT_HOST:80
let WEB_DESTINATION = '';
if (PORT && CERT_HOST) {
  WEB_DESTINATION = `${CERT_HOST}:80`;
  if (!/^[A-Za-z0-9.-]+:[0-9]{1,5}$/.test(WEB_DESTINATION)) die(`CERT_HOST='${CERT_HOST}' is invalid (expected a domain or an IPv4 address)`);
  console.log(`[WEB] Other paths on the front port are forwarded to ${WEB_DESTINATION}`);
}

// Hysteria2(UDP)、Mixed、WireGuard：只接受数字端口
const modePort = (name, v, desc) => {
  if (!v) return 0;
  if (!validPort(v)) die(`${name}='${v}' is invalid (expected a port number 1-65535, or empty to disable)`);
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
    let hasFront = false, hasReality = false;
    for (const token of (MODES[protocol] || '').split(',').map((s) => s.trim()).filter(Boolean)) {
      if (token === 'ws' || token === 'cloudflare') {
        if (hasFront) die(`${v}: only one of ws / cloudflare is allowed`);
        if (ACTIVE_MODE && ACTIVE_MODE !== token) die(`Protocols using ws / cloudflare share one port (PORT), so they must use the same mode (got: ${ACTIVE_MODE} ${token})`);
        hasFront = true; WS_PROTOCOLS.push(protocol); ACTIVE_MODE = token;
        continue;
      }
      if (hasReality) die(`${v}: only one Reality entry (a port or a fallback protocol) is allowed`);
      hasReality = true;
      if (/^[0-9]+$/.test(token)) {
        if (!validPort(token)) die(`${v}='${token}': port must be 1-65535`);
        NUMERIC_PORT[protocol] = +token;
      } else if (/^[a-z]+$/.test(token)) {
        if (!PROTOCOLS.includes(token)) die(`${v}='${token}' is not valid (expected ws / cloudflare / a port, or a fallback protocol: ${PROTOCOLS.join(' ')})`);
        if (token === protocol) die(`${v}='${token}': a protocol cannot fall back to itself`);
        if (protocol !== 'vless' && protocol !== 'trojan') die(`${v}='${token}': ${protocol.toUpperCase()} has no fallback ability, only VLESS and TROJAN can choose a fallback`);
        FALLBACK[protocol] = token;
      } else die(`${v}='${token}' is invalid (expected: ws / cloudflare / a port / a protocol name, comma separated, or empty to disable)`);
    }
  }
  QUICK_TUNNEL = ACTIVE_MODE === 'cloudflare' && CLOUDFLARE_TUNNEL_TOKEN === 'try';
}

// 2. 把回落关系整理成 Reality 链
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
    if (FALLBACK_PARENT[t]) die(`${t.toUpperCase()} is the fallback of both ${FALLBACK_PARENT[t].toUpperCase()} and ${p.toUpperCase()}, it can only have one`);
    FALLBACK_PARENT[t] = p;
  }
  for (const p of PROTOCOLS) {
    const hasReality = !!(NUMERIC_PORT[p] || FALLBACK[p]);
    if (WS_PROTOCOLS.includes(p) || hasReality || FALLBACK_PARENT[p]) ENABLED.push(p);
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
  for (const p of ENABLED) if ((NUMERIC_PORT[p] || FALLBACK[p] || FALLBACK_PARENT[p]) && !REALITY_PORT[p]) die(`${p.toUpperCase()} is part of a fallback loop: the chain needs a head that no protocol falls back to`);
}

// 3. 前置入口：是否需要、监听端口、是否与某条 Reality 链共用
function planFront() {
  if (!ACTIVE_MODE && !PORT) return;
  FRONT_ON = true;
  const fp = ACTIVE_MODE === 'cloudflare' ? DEFAULT_FRONT_PORT : (PORT || DEFAULT_FRONT_PORT);
  if (!validPort(String(fp))) die(`PORT='${PORT}' is not a valid port`);
  FRONT_PORT = +fp;
  if (PORT && ACTIVE_MODE !== 'cloudflare' && CHAIN_HEADS.some((h) => HEAD_PORT[h] === FRONT_PORT)) SHARE_FRONT = true;
}

// 4. 端口检查
function checkPorts() {
  const ports = CHAIN_HEADS.map((h) => HEAD_PORT[h]);
  if (FRONT_ON && !SHARE_FRONT) ports.push(FRONT_PORT);
  if (MIXED_PORT) ports.push(MIXED_PORT);
  const dup = ports.find((p, i) => ports.indexOf(p) !== i);
  if (dup !== undefined) die(`Port ${dup} is used more than once: every Reality chain, the ws / cloudflare group (PORT) and MIXED_MODE need different TCP ports`);
  const bad = ports.find((p) => p === SS_PORT || p === SS_WS_PORT);
  if (bad !== undefined) die(`Port ${bad} conflicts with the internal ports 40004 / 40005 used by Shadowsocks`);
}

// ========== TLS 证书(供 ws / Hysteria2 使用) ==========
// CERT_HOST 是域名且 WORK_DIR 下有可信的 $CERT_HOST.crt/.key -> 使用；否则自签证书
const IPV4_PATTERN = /^[0-9]{1,3}(\.[0-9]{1,3}){3}$/;
let CERT_FILE = '', KEY_FILE = '', TLS_SERVER_NAME = '', TLS_INSECURE = true, TLS_PINNED_CERT_SHA256 = '';

// 最小 DER 编码器：只够生成自签 X.509 证书
const Der = {
  length: (n) => (n < 128 ? Buffer.from([n]) : n < 256 ? Buffer.from([0x81, n]) : Buffer.from([0x82, n >> 8, n & 255])),
  tlv: (tag, ...kids) => { const body = Buffer.concat(kids); return Buffer.concat([Buffer.from([tag]), Der.length(body.length), body]); },
  seq: (...kids) => Der.tlv(0x30, ...kids),
  int: (b) => Der.tlv(0x02, b[0] & 0x80 ? Buffer.concat([Buffer.from([0]), b]) : b),
  oid: (dotted) => {
    const parts = dotted.split('.').map(Number), bytes = [parts[0] * 40 + parts[1]];
    for (const part of parts.slice(2)) { const enc = [part & 127]; for (let r = part >> 7; r; r >>= 7) enc.unshift((r & 127) | 128); bytes.push(...enc); }
    return Der.tlv(0x06, Buffer.from(bytes));
  },
  time: (d) => Der.tlv(0x17, Buffer.from(d.toISOString().replace(/^\d\d(\d\d)-(\d\d)-(\d\d)T(\d\d):(\d\d):(\d\d).*$/, '$1$2$3$4$5$6Z'))),
};

// 自签证书(RSA 2048，10 年)；已有且 30 天内不过期就复用(否则证书哈希变化会使订阅失效)
function generateSelfSignedCert(cn) {
  const dir = path.join(WORK_DIR, '.selfsigned');
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  CERT_FILE = path.join(dir, `${cn}.crt`); KEY_FILE = path.join(dir, `${cn}.key`);
  if (nonEmpty(CERT_FILE) && nonEmpty(KEY_FILE)) {
    try { if (Date.parse(new X509Certificate(fs.readFileSync(CERT_FILE)).validTo) - Date.now() > 30 * 86400e3) return; } catch { /* 重新生成 */ }
  }
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const subject = Der.seq(Der.tlv(0x31, Der.seq(Der.oid('2.5.4.3'), Der.tlv(0x0c, Buffer.from(cn)))));
  const sigAlg = Der.seq(Der.oid('1.2.840.113549.1.1.11'), Der.tlv(0x05));
  const serial = crypto.randomBytes(16); serial[0] = (serial[0] & 0x7f) || 1;
  const san = Der.tlv(0xa3, Der.seq(Der.seq(Der.oid('2.5.29.17'), Der.tlv(0x04, Der.seq(Der.tlv(0x82, Buffer.from(cn)), Der.tlv(0x82, Buffer.from('localhost')))))));
  const tbs = Der.seq(
    Der.tlv(0xa0, Der.int(Buffer.from([2]))), Der.int(serial), sigAlg, subject,
    Der.seq(Der.time(new Date(Date.now() - 86400e3)), Der.time(new Date(Date.now() + 3650 * 86400e3))), subject,
    publicKey.export({ type: 'spki', format: 'der' }), san,
  );
  const cert = Der.seq(tbs, sigAlg, Der.tlv(0x03, Buffer.concat([Buffer.from([0]), crypto.sign('sha256', tbs, privateKey)])));
  fs.writeFileSync(CERT_FILE, `-----BEGIN CERTIFICATE-----\n${toB64(cert).match(/.{1,64}/g).join('\n')}\n-----END CERTIFICATE-----\n`);
  fs.writeFileSync(KEY_FILE, privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });
}

// 校验证书链：叶子含域名，逐级验签，最终落在系统信任根上；返回空串表示可信，否则返回原因
function verifyChain(certs, host) {
  const leaf = certs[0];
  if (!leaf.checkHost(host)) return 'hostname mismatch';
  const roots = (tls.getCACertificates ? tls.getCACertificates('default') : tls.rootCertificates).map((p) => new X509Certificate(p));
  const valid = (c) => Date.now() >= Date.parse(c.validFrom) && Date.now() <= Date.parse(c.validTo);
  const signedBy = (c, issuer) => c.checkIssued(issuer) && c.verify(issuer.publicKey);
  let cur = leaf;
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
    if (!certs.length) throw new Error('no certificate found');
    if (!certs[0].checkPrivateKey(crypto.createPrivateKey(fs.readFileSync(keyFile)))) { console.error(`[TLS] ${certFile} and ${keyFile} do not match`); return false; }
  } catch (e) { console.error(`[TLS] Cannot read ${certFile} / ${keyFile}: ${e.message}`); return false; }
  const reason = verifyChain(certs, host);
  if (reason) { console.error(`[TLS] ${certFile} is not a trusted certificate for ${host}: ${reason}`); return false; }
  CERT_FILE = certFile; KEY_FILE = keyFile;
  return true;
}

function setupTls() {
  TLS_SERVER_NAME = CERT_HOST || 'www.nazhumi.com';
  TLS_INSECURE = !(CERT_HOST && !IPV4_PATTERN.test(CERT_HOST) && trustedCertForHost(CERT_HOST));
  if (TLS_INSECURE) {
    console.error(`[TLS] No trusted certificate available (put one at ${WORK_DIR}/<CERT_HOST>.crt and .key), using self-signed certificate`);
    generateSelfSignedCert(TLS_SERVER_NAME);
    TLS_PINNED_CERT_SHA256 = new X509Certificate(fs.readFileSync(CERT_FILE)).fingerprint256.replace(/:/g, '').toLowerCase();
  }
  console.log(`[TLS] Server name: ${TLS_SERVER_NAME}, insecure: ${TLS_INSECURE ? 1 : 0}, cert: ${CERT_FILE}, key: ${KEY_FILE}`);
}

// ========== 密钥 ==========
// 私钥由 UUID 派生(SHA-256 + 用途标签，按 X25519 规则整理)：同一 UUID 永远得到同一组密钥
function deriveKey(label, encoding) {
  const priv = crypto.createHash('sha256').update(`${label}:${UUID}`).digest();
  priv[0] &= 248; priv[31] = (priv[31] & 127) | 64;
  const pub = crypto.createPublicKey(crypto.createPrivateKey({
    key: Buffer.concat([Buffer.from('302e020100300506032b656e04220420', 'hex'), priv]), format: 'der', type: 'pkcs8',
  })).export({ type: 'spki', format: 'der' }).subarray(-32);
  return [priv.toString(encoding), Buffer.from(pub).toString(encoding)];
}

// ========== 链接里的连接地址 ==========
// CERT_HOST 填 IP -> 直接用；否则探测公网 IPv4，域名解析包含它时改用域名
let PUBLIC_ADDRESS = '';
const TRACE_URL = 'https://one.one.one.one/cdn-cgi/trace';

async function resolvePublicAddress() {
  if (IPV4_PATTERN.test(CERT_HOST)) PUBLIC_ADDRESS = CERT_HOST;
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

function protocolSettings(p, fallbacks, flow) {
  const fb = fallbacks ? { fallbacks } : {};
  switch (p) {
    case 'vless': return { clients: [{ id: UUID, email: UUID, ...(flow ? { flow } : {}) }], decryption: 'none', ...fb };
    case 'vmess': return { clients: [{ id: UUID, email: UUID }] };
    case 'trojan': return { clients: [{ password: UUID, email: UUID }], ...fb };
    case 'shadowsocks': return { method: 'aes-256-gcm', password: UUID, network: 'tcp' };
  }
}

const inbound = (tag, listen, port, protocol, settings, stream) => ({ tag, listen, port, protocol, settings, streamSettings: stream, sniffing: SNIFFING });

function buildConfig() {
  const inbounds = [];
  if (FRONT_ON) {
    // 前置入口：按路径把 ws 流量回落给各内部 ws 入口，其余回落给内置 HTTP 服务
    const fallbacks = [];
    for (const p of WS_PROTOCOLS) {
      const ep = wsInternalEndpoint(p);
      fallbacks.push({ path: WS_PATH[p], dest: ep.dest, xver: 0 });
      inbounds.push(inbound(`${p}-ws-in`, ep.listen, ep.port, p, protocolSettings(p), streamWs(WS_PATH[p])));
    }
    fallbacks.push({ dest: WEB_SOCKET, xver: 0 });
    const [listen, port] = SHARE_FRONT ? [FRONT_SOCKET, undefined] : ['::', FRONT_PORT];
    inbounds.push(inbound('front-in', listen, port, 'vless', protocolSettings('vless', fallbacks), FRONT_TLS ? streamTls('tcp', 'http/1.1') : streamTcp()));
  }
  for (const head of CHAIN_HEADS) { // Reality 链：链头监听自己的端口套 Reality；其余监听内部地址
    for (const p of CHAIN[head]) {
      const fallbacks = FALLBACK[p] ? [{ dest: internalEndpoint(FALLBACK[p]).dest, xver: 0 }] : undefined;
      if (p !== head) { const ep = internalEndpoint(p); inbounds.push(inbound(`${p}-in`, ep.listen, ep.port, p, protocolSettings(p, fallbacks), streamTcp())); continue; }
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
        ...(IPV6_AVAILABLE ? [] : [{ type: 'field', ip: ['::/0'], outboundTag: 'block' }]), // 无 IPv6 出口时拒绝 IPv6 目标
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
  const prefix = { vless: `encryption=none${VLESS_FLOW ? `&flow=${VLESS_FLOW}` : ''}&`, vmess: 'encryption=auto&' }[p] || '';
  const q = `security=reality&sni=${sni}&fp=chrome&pbk=${REALITY_PUBLIC_KEY}&type=tcp&sid=${REALITY_SHORT_ID}`;
  return `${p === 'shadowsocks' ? 'ss' : p}://${p === 'shadowsocks' ? SS_USERINFO : UUID}@${PUBLIC_ADDRESS}:${port}?${prefix}${q}#${urlEncode(name)}`;
}

// ws / cloudflare 链接的共同参数
function wsParams() {
  if (ACTIVE_MODE === 'cloudflare') return { address: CLOUDFLARE_IP || CF_HOSTNAME, port: 443, host: CF_HOSTNAME, insecureQuery: '', vmessInsecure: 0, vmessExtra: null, vmessPinnedCert: '' };
  const insecure = TLS_INSECURE ? 1 : 0;
  return {
    address: PUBLIC_ADDRESS, port: FRONT_PORT, host: TLS_SERVER_NAME, vmessInsecure: insecure, vmessPinnedCert: TLS_PINNED_CERT_SHA256,
    vmessExtra: { allowInsecure: insecure, verify_cert: !TLS_INSECURE }, insecureQuery: TLS_INSECURE ? `&allowInsecure=1&pcs=${TLS_PINNED_CERT_SHA256}` : '',
  };
}

function wsLink(p, w, name) {
  const encName = urlEncode(name), wsPath = WS_PATH[p], encPath = wsPath.replace(/\//g, '%2F');
  if (ACTIVE_MODE === 'cloudflare' && (!CF_HOSTNAME || !CLOUDFLARE_TUNNEL_TOKEN)) {
    console.error(`[MODE] cloudflare mode needs CLOUDFLARE_TUNNEL_TOKEN (set it to 'try' for a quick tunnel) and a tunnel hostname found in the cloudflared log, no ${p} link generated`);
    return '';
  }
  const q = `sni=${w.host}&fp=chrome&type=ws&host=${w.host}&path=${encPath}${w.insecureQuery}#${encName}`;
  switch (p) {
    case 'vless': return `vless://${UUID}@${w.address}:${w.port}?encryption=none&security=tls&${q}`;
    case 'trojan': return `trojan://${UUID}@${w.address}:${w.port}?security=tls&${q}`;
    case 'vmess': return `vmess://${toB64(JSON.stringify({
      v: '2', ps: name, add: w.address, port: String(w.port), id: UUID, aid: '0', scy: 'none', net: 'ws', type: 'none',
      host: w.host, path: wsPath + (ACTIVE_MODE === 'cloudflare' ? '?ed=2560' : ''), tls: 'tls', sni: w.host, alpn: '', fp: '', insecure: String(w.vmessInsecure), ...(w.vmessExtra || {}), vcn: '', pcs: w.vmessPinnedCert,
    }))}`; // ?ed=2560 为 0-RTT early data
    case 'shadowsocks': { // v2ray-plugin 无法跳过证书校验，自签证书下不输出
      if (ACTIVE_MODE === 'ws' && TLS_INSECURE) {
        console.error(`[MODE] ws mode: Shadowsocks (v2ray-plugin) needs a trusted certificate, put one at ${WORK_DIR}/<CERT_HOST>.crt and .key. No SS link generated`);
        return '';
      }
      const plugin = `v2ray-plugin;tls;host=${w.host};path=${wsPath};mux=0`.replace(/;/g, '%3B').replace(/=/g, '%3D').replace(/\//g, '%2F');
      return `ss://${SS_USERINFO}@${w.address}:${w.port}/?plugin=${plugin}#${encName}`;
    }
  }
}

// 一个协议可能输出两条链接(Reality + ws / cloudflare)，两条都有时节点名加后缀
function generateNodes(p, w) {
  const both = !!REALITY_PORT[p] && WS_PROTOCOLS.includes(p);
  return [
    REALITY_PORT[p] && realityLink(p, REALITY_PORT[p], both ? `${NAME}-reality` : NAME),
    WS_PROTOCOLS.includes(p) && wsLink(p, w, both ? `${NAME}-${ACTIVE_MODE}` : NAME),
  ].filter(Boolean);
}

const hysteria2Link = () => `hysteria2://${UUID}@${PUBLIC_ADDRESS}:${HYSTERIA2_PORT}/?sni=${TLS_SERVER_NAME}${TLS_INSECURE ? '&insecure=1' : ''}#${ENCODED_NAME}`;
const mixedLinks = () => ['socks5', 'http'].map((s) => `${s}://${UUID}:${UUID}@${PUBLIC_ADDRESS}:${MIXED_PORT}#${ENCODED_NAME}`).join('\n');
const wireguardLink = () => `wireguard://${urlEncode(WG_CLIENT_PRIV)}@${PUBLIC_ADDRESS}:${WIREGUARD_PORT}?publickey=${urlEncode(WG_SERVER_PUB)}&address=${urlEncode(WG_CLIENT_ADDR)}&mtu=1420#${ENCODED_NAME}`;
const wireguardConfig = () => `[Interface]\nPrivateKey = ${WG_CLIENT_PRIV}\nAddress = ${WG_CLIENT_ADDR}\nDNS = 1.1.1.1\nMTU = 1420\n\n[Peer]\nPublicKey = ${WG_SERVER_PUB}\nEndpoint = ${PUBLIC_ADDRESS}:${WIREGUARD_PORT}\nAllowedIPs = 0.0.0.0/0, ::/0\nPersistentKeepalive = 25\n`;

// ========== 内置 HTTP 服务(订阅 + 回落) ==========
// 监听 abstract unix socket：GET /UUID 返回 base64 订阅；其它路径转给 WEB_DESTINATION(没有就 404)
function startWeb(subBody) {
  const [dHost, dPort] = WEB_DESTINATION ? [WEB_DESTINATION.split(':')[0], +WEB_DESTINATION.split(':')[1]] : [];
  http.createServer((q, s) => {
    const pathname = q.url.split('?')[0];
    console.log(`[WEB] ${q.method} ${pathname === `/${UUID}` ? '/UUID' : pathname}`);
    if ((q.method === 'GET' || q.method === 'HEAD') && pathname === `/${UUID}`) {
      s.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store' });
      return s.end(q.method === 'HEAD' ? undefined : subBody);
    }
    if (!WEB_DESTINATION) { s.writeHead(404, { 'Content-Type': 'text/plain' }); return s.end('Not Found'); }
    const up = http.request({ host: dHost, port: dPort, path: q.url, method: q.method, headers: q.headers }, (ur) => { s.writeHead(ur.statusCode, ur.headers); ur.pipe(s); });
    up.on('error', () => { s.writeHead(502); s.end(); });
    q.pipe(up);
  }).on('error', (e) => console.error(`[WEB] HTTP service failed: ${e.message}`)).listen(`\0${WEB_SOCKET.slice(1)}`); // Node 里 abstract socket 以 \0 开头
}

// ========== 外部程序 ==========
async function fetchBinary(fileName, url) {
  const bin = path.join(WORK_DIR, fileName);
  if (!await download(bin, url)) process.exit(1);
  fs.chmodSync(bin, 0o755);
  return bin;
}

// Komari 探针：有代理协议时后台运行；没有时前台运行
async function startKomari() {
  await killPrevious('komari-agent', 'KOMARI');
  const bin = await fetchBinary('komari-agent', `https://github.com/komari-monitor/komari-agent/releases/latest/download/komari-agent-linux-${ARCH}`);
  const agentEnv = { AGENT_ENDPOINT: KOMARI_ENDPOINT, AGENT_TOKEN: KOMARI_TOKEN };
  if (XRAY_ON) {
    spawnBackground(bin, [], path.join(WORK_DIR, 'komari-agent.log'), agentEnv);
    return console.log(`[KOMARI] Agent started, reporting to ${KOMARI_ENDPOINT}`);
  }
  console.log(`[KOMARI] No proxy protocol enabled, running the agent only, reporting to ${KOMARI_ENDPOINT}`);
  const child = cp.spawn(bin, [], { env: { ...process.env, ...GO_ENV, ...agentEnv }, stdio: 'inherit' });
  children.push(child);
  child.on('exit', (code) => process.exit(code ?? 1));
  await new Promise(() => {});
}

// 取 cloudflared 日志里第一条「有具体域名、Service 是 http://localhost:端口」的 ingress 规则
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

// cloudflare 模式：Token 跑固定隧道；填 try 用临时隧道。域名和回源端口都从日志取
async function startCloudflared() {
  await killPrevious('cloudflared', 'CF');
  const bin = await fetchBinary('cloudflared', `https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-${ARCH}`);
  const logFile = path.join(WORK_DIR, 'cloudflared.log');
  cp.spawnSync(bin, ['--version'], { stdio: 'inherit' });

  if (QUICK_TUNNEL) {
    spawnBackground(bin, ['--no-autoupdate', 'tunnel', '--url', `http://localhost:${FRONT_PORT}`], logFile);
    for (let i = 0; i < 30 && !CF_HOSTNAME; i++) {
      CF_HOSTNAME = [...readLog(logFile).matchAll(/https:\/\/([a-z0-9-]+\.trycloudflare\.com)/g)].map((m) => m[1]).find((h) => !h.startsWith('api.')) || '';
      if (!CF_HOSTNAME) await sleep(1000);
    }
    if (CF_HOSTNAME) console.log(`[CF] Quick tunnel hostname from log: ${CF_HOSTNAME} (service port=${FRONT_PORT})`);
    else console.error(`[CF] Cannot find the trycloudflare.com hostname in ${logFile}`);
    return;
  }

  spawnBackground(bin, ['--no-autoupdate', 'tunnel', 'run'], logFile, { TUNNEL_TOKEN: CLOUDFLARE_TUNNEL_TOKEN });
  for (let i = 0; i < 30 && !readLog(logFile).includes('Updated to new configuration'); i++) await sleep(1000);
  const rule = parseIngress(readLog(logFile));
  if (rule && validPort(rule.port)) {
    CF_HOSTNAME = rule.hostname;
    FRONT_PORT = +rule.port;
    checkPorts();
    console.log(`[CF] From cloudflared log: hostname=${CF_HOSTNAME}, tunnel service port=${FRONT_PORT}`);
  } else console.error(`[CF] Cannot read hostname / port from ${logFile} (the tunnel needs a Public hostname without * and a Service like http://localhost:PORT)`);
}

// ========== 主流程 ==========
async function main() {
  parseModes();
  buildChains();
  planFront();
  FRONT_TLS = ACTIVE_MODE === 'ws' || SHARE_FRONT;
  checkPorts();

  if (ENABLED.length) console.log(`[MODE] enabled=${ENABLED.join(' ')}`);
  if (ACTIVE_MODE) console.log(`[MODE] port ${FRONT_PORT}: ${ACTIVE_MODE} (${WS_PROTOCOLS.join(' ')})${SHARE_FRONT ? ' shared with reality' : ''}`);
  for (const head of CHAIN_HEADS) console.log(`[MODE] port ${HEAD_PORT[head]}: reality (${CHAIN[head].join(' -> ')})`);
  VLESS_FLOW = CHAIN_HEADS.includes('vless') ? 'xtls-rprx-vision' : ''; // Vision 仅 VLESS 作 Reality 链头时支持

  const KOMARI_ON = !!(KOMARI_ENDPOINT && KOMARI_TOKEN);
  if (!XRAY_ON && !KOMARI_ON) die('Nothing to run: set a protocol *_MODE / HYSTERIA2_MODE / MIXED_MODE / WIREGUARD_MODE, or KOMARI_ENDPOINT + KOMARI_TOKEN');
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

  if (ACTIVE_MODE !== 'cloudflare' || CHAIN_HEADS.length || HYSTERIA2_PORT || MIXED_PORT || WIREGUARD_PORT) await resolvePublicAddress();
  IPV6_AVAILABLE = await request(TRACE_URL, { family: 6, timeout: 5000 }).then(() => true, () => false);
  console.log(IPV6_AVAILABLE ? '[NET] IPv6 egress: available' : '[NET] IPv6 egress: unavailable, blocking IPv6 destinations');
  if (FRONT_TLS || HYSTERIA2_PORT) setupTls();
  if (ACTIVE_MODE === 'cloudflare' && CLOUDFLARE_TUNNEL_TOKEN) await startCloudflared();

  // ---- Xray ----
  // 解压出 xray 后改名为 PROCESS_NAME(取自 NAME)，ps / top 里就显示这个名字
  const xrayBinary = path.join(WORK_DIR, PROCESS_NAME), extracted = path.join(WORK_DIR, 'xray');
  const configFile = path.join(WORK_DIR, 'config.json'), zipFile = path.join(WORK_DIR, 'xray.zip');
  await killPrevious(PROCESS_NAME, 'XRAY');
  if (!await download(zipFile, `https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-${ARCH === 'amd64' ? '64' : 'arm64-v8a'}.zip`)) process.exit(1);
  await unzip(zipFile, WORK_DIR);
  fs.rmSync(zipFile, { force: true });
  if (PROCESS_NAME !== 'xray') { try { fs.renameSync(extracted, xrayBinary); } catch (e) { console.error(`[XRAY] Cannot rename binary: ${e.message}`); } }
  try { fs.chmodSync(xrayBinary, 0o755); } catch { /* 下面统一检查 */ }
  if (!nonEmpty(xrayBinary)) { console.error(`[XRAY] Binary not found after extraction: ${xrayBinary}`); process.exit(1); }
  const xrayEnv = { ...process.env, ...GO_ENV, XRAY_LOCATION_ASSET: WORK_DIR };
  const runXray = (args) => cp.spawnSync(xrayBinary, args, { stdio: 'inherit', env: xrayEnv });
  runXray(['version']);

  fs.writeFileSync(configFile, '', { mode: 0o600 }); // 先收紧权限再写入(含 UUID 和 Reality 私钥)
  fs.chmodSync(configFile, 0o600);
  fs.writeFileSync(configFile, `${JSON.stringify(buildConfig(), null, 2)}\n`);
  if (runXray(['run', '-test', '-c', configFile]).status !== 0) { console.error('[XRAY] Config test failed, aborting'); process.exit(1); }

  // ---- 输出订阅 ----
  const wsInfo = ACTIVE_MODE ? wsParams() : null;
  const nodes = ENABLED.flatMap((p) => generateNodes(p, wsInfo));
  if (HYSTERIA2_PORT) nodes.push(hysteria2Link());
  if (MIXED_PORT) nodes.push(mixedLinks());
  if (WIREGUARD_PORT) nodes.push(wireguardLink());
  const allNodes = nodes.filter(Boolean).map((n) => `${n}\n`).join('');
  console.log(`\n=== Nodes ===\n${allNodes}\n=== Subscription (base64) ===\n${toB64(allNodes)}\n`);
  if (WIREGUARD_PORT) console.log(`\n=== WireGuard config (wg-quick) ===\n${wireguardConfig()}`);
  if (FRONT_ON) {
    startWeb(toB64(allNodes));
    const baseUrl = ACTIVE_MODE === 'cloudflare' ? (CF_HOSTNAME && `https://${CF_HOSTNAME}`) : `${FRONT_TLS ? 'https' : 'http'}://${PUBLIC_ADDRESS}:${FRONT_PORT}`;
    if (baseUrl) console.log(`\n=== Subscription URL ===\n${baseUrl}/${UUID}${FRONT_TLS && TLS_INSECURE ? '\n(自签证书：客户端需要允许不校验证书)' : ''}\n`);
  }

  // ---- systemd 服务文件 ----
  const serviceFile = path.join(WORK_DIR, `${SERVICE_NAME}.service`);
  fs.writeFileSync(serviceFile, [
    '[Unit]', `Description=${SERVICE_NAME}`, 'After=network.target', '',
    '[Service]', 'Type=simple', 'Restart=always', 'RestartSec=5', `WorkingDirectory=${WORK_DIR}`,
    `ExecStart=${process.execPath} ${SELF}`, 'KillMode=mixed', 'KillSignal=SIGTERM', '',
    '[Install]', 'WantedBy=multi-user.target', '',
  ].join('\n'));
  console.log(`\n=== systemd service (${SERVICE_NAME}) ===`);
  console.log(`cp ${serviceFile} /etc/systemd/system/${SERVICE_NAME}.service`);
  console.log(`systemctl daemon-reload && systemctl enable --now ${SERVICE_NAME}`);

  try { req('v8').setFlagsFromString('--expose-gc'); req('vm').runInNewContext('gc')(); } catch { /* 没有就算了 */ }
  const xrayProcess = cp.spawn(xrayBinary, ['run', '-c', configFile], { stdio: 'inherit', env: xrayEnv });
  children.push(xrayProcess);
  xrayProcess.on('exit', (code) => process.exit(code ?? 1));
}

main().catch((e) => { console.error(e); process.exit(1); });
