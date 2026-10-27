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
// 模式写法：ws / xhttp / 端口号 / 回落协议，多个用逗号分隔。配置了 CLOUDFLARE_TUNNEL_TOKEN 时 ws 与 xhttp 走 Cloudflare Tunnel
const CONFIG = {
  NAME: getEnv('NAME'),
  UUID: getEnv('UUID'),
  CLOUDFLARE_TUNNEL_TOKEN: getEnv('CLOUDFLARE_TUNNEL_TOKEN'),
  CLOUDFLARE_IP: getEnv('CLOUDFLARE_IP', 'www.gov.tw'),
  PORT: getEnv('PORT'),
  CERT_HOST: getEnv('CERT_HOST'),
  VLESS_MODE: getEnvMode('VLESS_MODE', 'trojan'),
  VMESS_MODE: getEnvMode('VMESS_MODE'),
  TROJAN_MODE: getEnvMode('TROJAN_MODE', 'vmess'),
  SHADOWSOCKS_MODE: getEnvMode('SHADOWSOCKS_MODE'),
  HYSTERIA2_MODE: getEnv('HYSTERIA2_MODE'),
  MIXED_MODE: getEnv('MIXED_MODE'),
  WIREGUARD_MODE: getEnv('WIREGUARD_MODE'),
  WORK_DIR: getEnv('WORK_DIR'),
  KOMARI_ENDPOINT: getEnv('KOMARI_ENDPOINT'),
  KOMARI_TOKEN: getEnv('KOMARI_TOKEN'),
  LOG_LEVEL: getEnvMode('LOG_LEVEL', 'warning'),
};
normalizeConfig();
if (CONFIG.LOG_LEVEL !== 'none') persistEnv(ENV_FILE);
const { NAME, UUID, CLOUDFLARE_TUNNEL_TOKEN, CLOUDFLARE_IP, PORT, VLESS_MODE, VMESS_MODE, TROJAN_MODE, SHADOWSOCKS_MODE,
  HYSTERIA2_MODE, MIXED_MODE, WIREGUARD_MODE, CERT_HOST, KOMARI_ENDPOINT, KOMARI_TOKEN, LOG_LEVEL } = CONFIG;

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
function normalizeConfig() {
  CONFIG.UUID = CONFIG.UUID || crypto.randomUUID();
  CONFIG.PORT = CONFIG.PORT.replace(/^0+$/, '');
  CONFIG.CERT_HOST = CONFIG.CERT_HOST.replace(/^[a-z]+:\/\//i, '').replace(/[/:].*$/, '');
}
// 把配置持久化到 .env(权限 600)，并把脚本中的 CONFIG 改为只读环境变量
function persistEnv(f) {
  const fmt = (k, v) => `${k}=${/[\s#'"]/.test(v) ? `"${v}"` : v}`;
  let text = readText(f);
  for (const [k, v] of Object.entries(CONFIG)) {
    const re = new RegExp(`^\\s*(?:export\\s+)?${k}\\s*=.*$`, 'm');
    text = re.test(text) ? text.replace(re, () => fmt(k, v)) : `${text}${text && !text.endsWith('\n') ? '\n' : ''}${fmt(k, v)}\n`;
  }
  try { fs.writeFileSync(f, text, { mode: 0o600 }); fs.chmodSync(f, 0o600); }
  catch (e) { console.error(`[ENV] Cannot write ${f}: ${e.message}`); }
  rewriteConfigToEnvReads();
}
function rewriteConfigToEnvReads() {
  try {
    const src = fs.readFileSync(SCRIPT_PATH, 'utf8');
    const block = src.match(/^const CONFIG = \{\n[\s\S]*?\n\};/m);
    if (!block) return console.error('[ENV] CONFIG block not found, script not rewritten');
    const rewritten = block[0].replace(/^  ([A-Z0-9_]+): .*$/gm, (line, k) => (k in CONFIG
      ? `  ${k}: ${/_MODE$|^LOG_LEVEL$/.test(k) ? 'getEnvMode' : 'getEnv'}('${k}'),` : line));
    fs.writeFileSync(SCRIPT_PATH, src.replace(block[0], () => rewritten));
  } catch (e) { console.error(`[ENV] Cannot rewrite script: ${e.message}`); }
}

const toBase64 = (d) => Buffer.from(d).toString('base64');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const validPort = (v) => /^\d+$/.test(v) && +v >= 1 && +v <= 65535;
const nonEmpty = (f) => { try { return fs.statSync(f).size > 0; } catch { return false; } };
const urlEncode = (t) => encodeURIComponent(t).replace(/[!'()*]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`);

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

// Go 程序内存参数：有容器内存限制时关闭 GOGC 交给 GOMEMLIMIT 统一管理(减少 GC 开销)，否则 GOGC=50 省内存
const GO_ENV = (() => {
  const limit = +(readText('/sys/fs/cgroup/memory.max').trim() || readText('/sys/fs/cgroup/memory/memory.limit_in_bytes').trim());
  return limit > 0 && limit < 2 ** 40
    ? { GOGC: 'off', GOMEMLIMIT: `${Math.floor(limit * 0.6 / 1048576)}MiB` }
    : { GOGC: '50' };
})();

const childProcesses = [];
process.on('exit', () => childProcesses.forEach((c) => { try { c.kill(); } catch {} }));
for (const sig of ['SIGINT', 'SIGTERM']) process.on(sig, () => process.exit(0));

async function killPrevious(name, tag) {
  try { cp.execFileSync('pkill', ['-x', name], { stdio: 'ignore' }); } catch { return; }
  console.log(`[${tag}] Stopped previous ${name}`);
  await sleep(1000);
}

function spawnBackground(bin, args, logFile, env = {}) {
  const fd = fs.openSync(logFile, 'w');
  const child = cp.spawn(bin, args, { env: { ...process.env, ...GO_ENV, ...env }, stdio: ['ignore', fd, fd] });
  fs.closeSync(fd);
  childProcesses.push(child);
  return child;
}

// ========== 协议与模式 ==========
const PROTOCOLS = ['vless', 'vmess', 'trojan', 'shadowsocks'];
const WS_PATH = Object.fromEntries(PROTOCOLS.map((p) => [p, `/${UUID}-${p === 'shadowsocks' ? 'ss' : p}`]));
const XHTTP_PATH = Object.fromEntries(PROTOCOLS.map((p) => [p, `/${UUID}-${p}-xhttp`]));
const SS_PORT = 40004, SS_WS_PORT = 40005;
const abstractSock = (name) => `@xray-${crypto.createHash('sha1').update(BASE_DIR).digest('hex').slice(0, 8)}-${name}`;
const endpoint = (p, name, ssPort) => (p === 'shadowsocks'
  ? { listen: '127.0.0.1', port: ssPort, dest: ssPort }
  : { listen: abstractSock(name), dest: abstractSock(name) });
const internalEp = (p) => endpoint(p, p, SS_PORT);
const wsEp = (p) => endpoint(p, `${p}-ws`, SS_WS_PORT);
const xhttpEp = (p) => endpoint(p, `${p}-xhttp`);
const FRONT_SOCKET = abstractSock('front'), WEB_SOCKET = abstractSock('web');
const DEFAULT_FRONT_PORT = 8000, WG_CLIENT_ADDR = '10.0.0.2/32';
const MODES = { vless: VLESS_MODE, vmess: VMESS_MODE, trojan: TROJAN_MODE, shadowsocks: SHADOWSOCKS_MODE };
const NUMERIC_PORT = {}, FALLBACK = {}, FALLBACK_PARENT = {}, CHAIN = {}, HEAD_PORT = {}, REALITY_PORT = {};
const ENABLED = [], WS_PROTOCOLS = [], XHTTP_PROTOCOLS = [], CHAIN_HEADS = [];
const FRONT_PROTOCOLS = () => [...new Set([...WS_PROTOCOLS, ...XHTTP_PROTOCOLS])];
const frontSummary = () => [['ws', WS_PROTOCOLS], ['xhttp', XHTTP_PROTOCOLS]]
  .filter(([, l]) => l.length).map(([n, l]) => `${n} (${l.join(' ')})`).join(', ');
let QUICK_TUNNEL = false, FRONT_ON = false, CF_ON = false, SHARE_FRONT = false, FRONT_TLS = false;
let FRONT_PORT = 0, CF_PORT = 0, XRAY_ON = false;
const ENCODED_NAME = urlEncode(NAME);

// 前置入口的非 ws/xhttp 请求回落到内置 HTTP 服务
let WEB_DESTINATION = '';
if (PORT && CERT_HOST) {
  WEB_DESTINATION = `${CERT_HOST}:80`;
  if (!/^[A-Za-z0-9.-]+:\d{1,5}$/.test(WEB_DESTINATION)) die(`[WEB] CERT_HOST='${CERT_HOST}' is invalid (expected a domain or an IPv4 address)`);
  console.log(`[WEB] Other paths on the front port are forwarded to ${WEB_DESTINATION}`);
}

const modePort = (name, value, desc) => {
  if (!value) return 0;
  if (!validPort(value)) die(`[MODE] ${name}='${value}' is invalid (expected a port 1-65535, or empty to disable)`);
  console.log(`[MODE] port ${+value}/${desc}`);
  return +value;
};
const HYSTERIA2_PORT = modePort('HYSTERIA2_MODE', HYSTERIA2_MODE, 'udp: hysteria2');
const MIXED_PORT = modePort('MIXED_MODE', MIXED_MODE, 'tcp: mixed (socks5 + http)');
const WIREGUARD_PORT = modePort('WIREGUARD_MODE', WIREGUARD_MODE, 'udp: wireguard');

// 1. 解析各协议的 *_MODE
function parseModes() {
  for (const p of PROTOCOLS) {
    const env = `${p.toUpperCase()}_MODE`;
    let hasReality = false;
    for (const t of (MODES[p] || '').split(',').map((s) => s.trim()).filter(Boolean)) {
      if (t === 'cloudflare') die(`[MODE] ${env}: 'cloudflare' mode was removed, use ws or xhttp together with CLOUDFLARE_TUNNEL_TOKEN`);
      if (t === 'ws' || t === 'xhttp') {
        if (t === 'xhttp' && p === 'shadowsocks') die(`[MODE] ${env}: xhttp is not supported for shadowsocks (no common client support)`);
        const list = t === 'ws' ? WS_PROTOCOLS : XHTTP_PROTOCOLS;
        if (list.includes(p)) die(`[MODE] ${env}: '${t}' is given more than once`);
        list.push(p);
        continue;
      }
      if (hasReality) die(`[MODE] ${env}: only one Reality entry (a port or a fallback protocol) is allowed`);
      hasReality = true;
      if (/^\d+$/.test(t)) {
        if (!validPort(t)) die(`[MODE] ${env}='${t}': port must be 1-65535`);
        NUMERIC_PORT[p] = +t;
      } else if (/^[a-z]+$/.test(t)) {
        if (!PROTOCOLS.includes(t)) die(`[MODE] ${env}='${t}' is not valid`);
        if (t === p) die(`[MODE] ${env}='${t}': a protocol cannot fall back to itself`);
        if (!['vless', 'trojan'].includes(p)) die(`[MODE] ${env}='${t}': only VLESS and TROJAN can choose a fallback`);
        FALLBACK[p] = t;
      } else die(`[MODE] ${env}='${t}' is invalid`);
    }
  }
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
  for (const h of CHAIN_HEADS) {
    let tail = h;
    CHAIN[h] = [h];
    while (FALLBACK[tail]) { tail = FALLBACK[tail]; CHAIN[h].push(tail); }
    HEAD_PORT[h] = NUMERIC_PORT[tail];
    for (const p of CHAIN[h]) REALITY_PORT[p] = HEAD_PORT[h];
  }
  XRAY_ON = ENABLED.length > 0 || !!(HYSTERIA2_PORT || MIXED_PORT || WIREGUARD_PORT);
  for (const p of ENABLED) {
    if ((NUMERIC_PORT[p] || FALLBACK[p] || FALLBACK_PARENT[p]) && !REALITY_PORT[p]) die(`[MODE] ${p.toUpperCase()} is part of a fallback loop`);
  }
}

// 3. 前置入口规划：配置了 Cloudflare token 且有 ws/xhttp 时走隧道，否则直连 PORT
function planFront() {
  CF_ON = !!CLOUDFLARE_TUNNEL_TOKEN && FRONT_PROTOCOLS().length > 0;
  FRONT_ON = CF_ON || FRONT_PROTOCOLS().length > 0 || !!PORT;
  if (CF_ON) {
    if (PORT) console.log('[MODE] PORT is ignored: ws/xhttp are served through the Cloudflare Tunnel');
    return;
  }
  if (!FRONT_ON) return;
  if (PORT && !validPort(PORT)) die(`[MODE] PORT='${PORT}' is not a valid port`);
  FRONT_PORT = +(PORT || DEFAULT_FRONT_PORT);
  if (PORT && CHAIN_HEADS.some((h) => HEAD_PORT[h] === FRONT_PORT)) SHARE_FRONT = true;
}

// 4. 端口检查
function checkPorts() {
  const used = CHAIN_HEADS.map((h) => HEAD_PORT[h]);
  if (FRONT_ON && !CF_ON && !SHARE_FRONT) used.push(FRONT_PORT);
  if (CF_ON && CF_PORT) used.push(CF_PORT);
  if (MIXED_PORT) used.push(MIXED_PORT);
  const dup = used.find((p, i) => used.indexOf(p) !== i);
  if (dup !== undefined) die(`[MODE] Port ${dup} is used more than once`);
  const conflict = used.find((p) => p === SS_PORT || p === SS_WS_PORT);
  if (conflict !== undefined) die(`[MODE] Port ${conflict} conflicts with the internal ports 40004 / 40005 used by Shadowsocks`);
}

// ========== TLS 证书 ==========
const IPV4 = /^\d{1,3}(\.\d{1,3}){3}$/;
let CERT_FILE = '', KEY_FILE = '', TLS_SERVER_NAME = '', TLS_INSECURE = true, TLS_PINNED_CERT_SHA256 = '';

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
    TLS_PINNED_CERT_SHA256 = new X509Certificate(fs.readFileSync(CERT_FILE)).fingerprint256.replace(/:/g, '').toLowerCase();
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

// ========== 链接地址 ==========
let PUBLIC_ADDRESS = '';
const TRACE_URL = 'https://one.one.one.one/cdn-cgi/trace';

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
let REALITY_PRIVATE_KEY = '', REALITY_PUBLIC_KEY = '', REALITY_SHORT_ID = '', VLESS_FLOW = '', IPV6_AVAILABLE = false;
let WG_SERVER_PRIV = '', WG_SERVER_PUB = '', WG_CLIENT_PRIV = '', WG_CLIENT_PUB = '';
const SNIFFING = { enabled: true, destOverride: ['http', 'tls', 'quic'], routeOnly: true };

const streamTcp = () => ({ network: 'tcp', security: 'none' });
const streamWs = (p) => ({ network: 'ws', security: 'none', wsSettings: { path: p } });
const streamXhttp = (p) => ({ network: 'xhttp', security: 'none', xhttpSettings: { path: p, mode: 'auto' } });
const streamReality = (dest = 'www.iij.ad.jp:443', serverName = 'www.iij.ad.jp') => ({
  network: 'tcp', security: 'reality',
  realitySettings: { show: false, dest, xver: 0, serverNames: [serverName], privateKey: REALITY_PRIVATE_KEY, shortIds: [REALITY_SHORT_ID] },
});
const streamTls = (network, alpn, extra = {}) => ({
  network, security: 'tls',
  tlsSettings: { serverName: TLS_SERVER_NAME, alpn: [alpn], certificates: [{ certificateFile: CERT_FILE, keyFile: KEY_FILE }] },
  ...extra,
});
const inbound = (tag, listen, port, protocol, settings, streamSettings) => ({ tag, listen, port, protocol, settings, streamSettings, sniffing: SNIFFING });

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
  for (const p of WS_PROTOCOLS) {
    const e = wsEp(p);
    inbounds.push(inbound(`${p}-ws-in`, e.listen, e.port, p, protocolSettings(p), streamWs(WS_PATH[p])));
  }
  for (const p of XHTTP_PROTOCOLS) {
    const e = xhttpEp(p);
    inbounds.push(inbound(`${p}-xhttp-in`, e.listen, undefined, p, protocolSettings(p), streamXhttp(XHTTP_PATH[p])));
  }
  if (FRONT_ON) {
    const frontFallbacks = [
      ...WS_PROTOCOLS.map((p) => ({ path: WS_PATH[p], dest: wsEp(p).dest, xver: 0 })),
      ...XHTTP_PROTOCOLS.map((p) => ({ path: XHTTP_PATH[p], dest: xhttpEp(p).dest, xver: 0 })),
      { dest: WEB_SOCKET, xver: 0 },
    ];
    const [listen, port] = CF_ON ? ['::', CF_PORT] : (SHARE_FRONT ? [FRONT_SOCKET, undefined] : ['::', FRONT_PORT]);
    inbounds.push(inbound('front-in', listen, port, 'vless', protocolSettings('vless', frontFallbacks),
      FRONT_TLS ? streamTls('tcp', 'http/1.1') : streamTcp()));
  }
  for (const head of CHAIN_HEADS) {
    for (const p of CHAIN[head]) {
      const fallbacks = FALLBACK[p] ? [{ dest: internalEp(FALLBACK[p]).dest, xver: 0 }] : undefined;
      if (p !== head) {
        const e = internalEp(p);
        inbounds.push(inbound(`${p}-in`, e.listen, e.port, p, protocolSettings(p, fallbacks), streamTcp()));
        continue;
      }
      const stream = SHARE_FRONT && HEAD_PORT[head] === FRONT_PORT ? streamReality(FRONT_SOCKET, TLS_SERVER_NAME) : streamReality();
      inbounds.push(inbound(`${p}-in`, '::', HEAD_PORT[head], p, protocolSettings(p, fallbacks, p === 'vless' ? VLESS_FLOW : ''), stream));
    }
  }
  if (HYSTERIA2_PORT) inbounds.push(inbound('hysteria2-in', '::', HYSTERIA2_PORT, 'hysteria',
    { version: 2, clients: [{ auth: UUID, email: UUID }] }, streamTls('hysteria', 'h3', { hysteriaSettings: { version: 2 } })));
  if (MIXED_PORT) inbounds.push(inbound('mixed-in', '::', MIXED_PORT, 'socks',
    { auth: 'password', accounts: [{ user: UUID, pass: UUID }], udp: false }, streamTcp()));
  if (WIREGUARD_PORT) inbounds.push(inbound('wireguard-in', '::', WIREGUARD_PORT, 'wireguard',
    { secretKey: WG_SERVER_PRIV, peers: [{ publicKey: WG_CLIENT_PUB, allowedIPs: [WG_CLIENT_ADDR] }], mtu: 1420 }));

  return {
    log: { loglevel: LOG_LEVEL },
    // 空闲连接 180 秒后回收，降低长期占用的连接数与内存
    policy: { levels: { 0: { handshake: 4, connIdle: 180, uplinkOnly: 2, downlinkOnly: 5 } } },
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
  const enc = p === 'vless' ? `encryption=none${VLESS_FLOW ? `&flow=${VLESS_FLOW}` : ''}&` : p === 'vmess' ? 'encryption=auto&' : '';
  const q = `security=reality&sni=${sni}&fp=chrome&pbk=${REALITY_PUBLIC_KEY}&type=tcp&sid=${REALITY_SHORT_ID}`;
  const isSs = p === 'shadowsocks';
  return `${isSs ? 'ss' : p}://${isSs ? SS_USERINFO : UUID}@${PUBLIC_ADDRESS}:${port}?${enc}${q}#${urlEncode(name)}`;
}

// 前置入口的连接参数：走 Cloudflare Tunnel 时用 CF 域名 443，否则用直连地址
function frontParams() {
  if (CF_ON) return { viaCf: true, address: CLOUDFLARE_IP || CF_HOSTNAME, port: 443, host: CF_HOSTNAME, insecure: 0, pinned: '', extra: null, query: '' };
  const insecure = TLS_INSECURE ? 1 : 0;
  return {
    viaCf: false, address: PUBLIC_ADDRESS, port: FRONT_PORT, host: TLS_SERVER_NAME, insecure, pinned: TLS_PINNED_CERT_SHA256,
    extra: { allowInsecure: insecure, verify_cert: !TLS_INSECURE },
    query: TLS_INSECURE ? `&allowInsecure=1&pcs=${TLS_PINNED_CERT_SHA256}` : '',
  };
}

const frontTransports = (p) => [...(WS_PROTOCOLS.includes(p) ? ['ws'] : []), ...(XHTTP_PROTOCOLS.includes(p) ? ['xhttp'] : [])];

function frontLink(p, transport, params, name) {
  const linkPath = transport === 'xhttp' ? XHTTP_PATH[p] : WS_PATH[p];
  const encName = urlEncode(name);
  const query = `sni=${params.host}&fp=chrome&type=${transport}&host=${params.host}&path=${urlEncode(linkPath)}${transport === 'xhttp' ? '&mode=auto' : ''}${params.query}#${encName}`;
  switch (p) {
    case 'vless': return `vless://${UUID}@${params.address}:${params.port}?encryption=none&security=tls&${query}`;
    case 'trojan': return `trojan://${UUID}@${params.address}:${params.port}?security=tls&${query}`;
    case 'vmess': return `vmess://${toBase64(JSON.stringify({
      v: '2', ps: name, add: params.address, port: String(params.port), id: UUID, aid: '0', scy: 'none', net: transport, type: 'none',
      host: params.host, path: linkPath + (params.viaCf && transport === 'ws' ? '?ed=2560' : ''), tls: 'tls', sni: params.host, alpn: '', fp: '',
      insecure: String(params.insecure), ...(params.extra || {}), vcn: '', pcs: params.pinned,
    }))}`;
    case 'shadowsocks': {
      if (TLS_INSECURE && !params.viaCf) {
        console.error('[MODE] ws mode: Shadowsocks (v2ray-plugin) needs a trusted certificate, no SS link generated');
        return '';
      }
      const plugin = `v2ray-plugin;tls;host=${params.host};path=${linkPath};mux=0`.replace(/;/g, '%3B').replace(/=/g, '%3D').replace(/\//g, '%2F');
      return `ss://${SS_USERINFO}@${params.address}:${params.port}/?plugin=${plugin}#${encName}`;
    }
  }
}

const realityNodes = () => ENABLED.filter((p) => REALITY_PORT[p]).map((p) => realityLink(p, REALITY_PORT[p], NAME));

function frontNodes() {
  if (!FRONT_PROTOCOLS().length || (CF_ON && !CF_HOSTNAME)) return [];
  const params = frontParams();
  return ENABLED.flatMap((p) => {
    const ts = frontTransports(p);
    return ts.map((t) => frontLink(p, t, params, (REALITY_PORT[p] || ts.length > 1) ? `${NAME}-${t}` : NAME));
  });
}

const hysteria2Link = () => `hysteria2://${UUID}@${PUBLIC_ADDRESS}:${HYSTERIA2_PORT}/?sni=${TLS_SERVER_NAME}${TLS_INSECURE ? '&insecure=1' : ''}#${ENCODED_NAME}`;
const mixedLinks = () => ['socks5', 'http'].map((s) => `${s}://${UUID}:${UUID}@${PUBLIC_ADDRESS}:${MIXED_PORT}#${ENCODED_NAME}`).join('\n');
const wireguardLink = () => `wireguard://${urlEncode(WG_CLIENT_PRIV)}@${PUBLIC_ADDRESS}:${WIREGUARD_PORT}?publickey=${urlEncode(WG_SERVER_PUB)}&address=${urlEncode(WG_CLIENT_ADDR)}&mtu=1420#${ENCODED_NAME}`;
const wireguardConfig = () => `[Interface]\nPrivateKey = ${WG_CLIENT_PRIV}\nAddress = ${WG_CLIENT_ADDR}\nDNS = 1.1.1.1\nMTU = 1420\n\n[Peer]\nPublicKey = ${WG_SERVER_PUB}\nEndpoint = ${PUBLIC_ADDRESS}:${WIREGUARD_PORT}\nAllowedIPs = 0.0.0.0/0, ::/0\nPersistentKeepalive = 25\n`;

// ========== 内置 HTTP 服务(订阅 + xhttp 转发 + 回落) ==========
// 复用到 Xray abstract socket / 回落目标的长连接，避免每个请求都新建 TCP/Unix 连接
const upstreamAgent = new http.Agent({ keepAlive: true, keepAliveMsecs: 30000, maxSockets: 512 });

function startWeb(subscriptionBody) {
  const [destHost, destPort] = WEB_DESTINATION.split(':');
  const xhttpRoutes = Object.entries(XHTTP_PATH).map(([p, prefix]) => ({
    prefix, socketPath: `\0${xhttpEp(p).listen.slice(1)}`,
  }));
  http.createServer((req, res) => {
    const pathname = req.url.split('?')[0];
    const route = xhttpRoutes.find(({ prefix }) => pathname === prefix || pathname.startsWith(`${prefix}/`));
    const forward = (opts) => {
      const up = http.request({ ...opts, path: req.url, method: req.method, headers: req.headers, agent: upstreamAgent }, (ur) => {
        res.writeHead(ur.statusCode, ur.headers);
        ur.pipe(res);
      });
      up.on('error', () => { if (!res.headersSent) res.writeHead(502); res.end(); });
      req.pipe(up);
    };
    if (route) return forward({ socketPath: route.socketPath });

    console.log(`[WEB] ${req.method} ${pathname === `/${UUID}` ? '/UUID' : pathname}`);
    if ((req.method === 'GET' || req.method === 'HEAD') && pathname === `/${UUID}`) {
      res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store' });
      return res.end(req.method === 'HEAD' ? undefined : subscriptionBody);
    }
    if (!WEB_DESTINATION) { res.writeHead(404, { 'Content-Type': 'text/plain' }); return res.end('Not Found'); }
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
  const env = { AGENT_ENDPOINT: KOMARI_ENDPOINT, AGENT_TOKEN: KOMARI_TOKEN };
  if (XRAY_ON) {
    spawnBackground(bin, [], QUIET ? '/dev/null' : path.join(WORK_DIR, `${svc}.log`), env);
    return console.log(`[KOMARI] Agent started, reporting to ${KOMARI_ENDPOINT}`);
  }
  console.log(`[KOMARI] No proxy protocol enabled, running the agent only, reporting to ${KOMARI_ENDPOINT}`);
  const child = cp.spawn(bin, [], { env: { ...process.env, ...GO_ENV, ...env }, stdio: STDIO });
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
  const fail = (msg) => { console.error(`[CF] ${msg}`); process.exit(1); };
  cp.spawnSync(bin, ['--version'], { stdio: STDIO });

  if (QUICK_TUNNEL) {
    CF_PORT = DEFAULT_FRONT_PORT;
    checkPorts();
    spawnBackground(bin, ['--no-autoupdate', 'tunnel', '--url', `http://localhost:${CF_PORT}`], logFile);
    for (let i = 0; i < 30 && !CF_HOSTNAME; i++) {
      CF_HOSTNAME = [...readText(logFile).matchAll(/https:\/\/([a-z0-9-]+\.trycloudflare\.com)/g)]
        .map((m) => m[1]).find((h) => !h.startsWith('api.')) || '';
      if (!CF_HOSTNAME) await sleep(1000);
    }
    if (!CF_HOSTNAME) fail(`Cannot find the trycloudflare.com hostname in ${logFile}, exiting`);
    console.log(`[CF] Quick tunnel hostname: ${CF_HOSTNAME} (service port=${CF_PORT})`);
  } else {
    spawnBackground(bin, ['--no-autoupdate', 'tunnel', 'run'], logFile, { TUNNEL_TOKEN: CLOUDFLARE_TUNNEL_TOKEN });
    for (let i = 0; i < 30 && !readText(logFile).includes('Updated to new configuration'); i++) await sleep(1000);
    const rule = parseIngress(readText(logFile));
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
  QUICK_TUNNEL = CF_ON && CLOUDFLARE_TUNNEL_TOKEN === 'try';
  FRONT_TLS = !CF_ON && (FRONT_PROTOCOLS().length > 0 || SHARE_FRONT);
  checkPorts();

  if (ENABLED.length) console.log(`[MODE] enabled=${ENABLED.join(' ')}`);
  if (CF_ON) console.log(`[MODE] cloudflare tunnel (${QUICK_TUNNEL ? 'quick' : 'fixed'}): ${frontSummary()} (tunnel port decided by cloudflared log)`);
  else if (FRONT_ON) console.log(`[MODE] port ${FRONT_PORT}: ${frontSummary() || 'subscription only'}${SHARE_FRONT ? ' shared with reality' : ''}`);
  for (const h of CHAIN_HEADS) console.log(`[MODE] port ${HEAD_PORT[h]}: reality (${CHAIN[h].join(' -> ')})`);
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

  if ((FRONT_ON && !CF_ON) || CHAIN_HEADS.length || HYSTERIA2_PORT || MIXED_PORT || WIREGUARD_PORT) await resolvePublicAddress();
  IPV6_AVAILABLE = await request(TRACE_URL, { family: 6, timeout: 5000 }).then(() => true, () => false);
  console.log(IPV6_AVAILABLE ? '[NET] IPv6 egress: available' : '[NET] IPv6 egress: unavailable, blocking IPv6 destinations');
  if (FRONT_TLS || HYSTERIA2_PORT) setupTls();
  if (CF_ON) await startCloudflared();

  // ---- Xray ----
  const xrayBin = path.join(WORK_DIR, `xray-${hp}`), extracted = path.join(WORK_DIR, 'xray');
  const configFile = path.join(WORK_DIR, 'config.json'), zipFile = path.join(WORK_DIR, 'xray.zip');
  await killPrevious(`xray-${hp}`, 'XRAY');
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
  if (runXray(['run', '-test', '-c', configFile]).status !== 0) die('[XRAY] Config test failed, aborting');

  // ---- 订阅输出 ----
  const nodes = [
    ...realityNodes(),
    ...frontNodes(),
    HYSTERIA2_PORT && hysteria2Link(),
    WIREGUARD_PORT && wireguardLink(),
    MIXED_PORT && mixedLinks(),
  ];
  const allNodes = nodes.filter(Boolean).map((n) => `${n}\n`).join('');
  console.log(`\n=== Nodes ===\n${allNodes}\n=== Subscription (base64) ===\n${toBase64(allNodes)}\n`);
  if (WIREGUARD_PORT) console.log(`\n=== WireGuard config (wg-quick) ===\n${wireguardConfig()}`);
  if (FRONT_ON) {
    startWeb(toBase64(allNodes));
    const bases = CF_ON
      ? (CF_HOSTNAME ? [`https://${CF_HOSTNAME}`] : [])
      : [`${FRONT_TLS ? 'https' : 'http'}://${PUBLIC_ADDRESS}:${FRONT_PORT}`];
    if (bases.length) console.log(`\n=== Subscription URL ===\n${bases.map((b) => `${b}/${UUID}`).join('\n')}${FRONT_TLS && TLS_INSECURE ? '\n(自签证书：客户端需要允许不校验证书)' : ''}\n`);
  }

  // ---- systemd 服务文件(限制 Node 自身堆内存) ----
  const serviceName = `cache-${uuidHash.slice(0, 6)}`;
  const serviceFile = path.join(WORK_DIR, `${serviceName}.service`);
  fs.writeFileSync(serviceFile, `[Unit]\nDescription=${serviceName}\nAfter=network.target\n\n[Service]\nType=simple\nRestart=always\nRestartSec=5\nWorkingDirectory=${WORK_DIR}\nExecStart=${process.execPath} --max-old-space-size=48 ${SCRIPT_PATH}\nKillMode=mixed\nKillSignal=SIGTERM\n\n[Install]\nWantedBy=multi-user.target\n`);
  console.log(`\n=== systemd service (${serviceName}) ===\ncp ${serviceFile} /etc/systemd/system/${serviceName}.service\nsystemctl daemon-reload && systemctl enable --now ${serviceName}`);

  const xrayProcess = cp.spawn(xrayBin, ['run', '-c', configFile], { stdio: STDIO, env: xrayEnv });
  childProcesses.push(xrayProcess);
  xrayProcess.on('exit', (code) => process.exit(code ?? 1));
}

main().catch((e) => { console.error(e); process.exit(1); });
