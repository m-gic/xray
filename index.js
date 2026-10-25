#!/usr/bin/env node
'use strict';
// 纯 Node.js(>=16)，除自签证书需要系统 openssl 外仅使用内置模块
const requireBuiltin = (moduleName) => (typeof require === 'function' ? require(moduleName) : process.getBuiltinModule(`node:${moduleName}`));
const [crypto, fs, path, childProcess, https, http, zlib, dns, tls] = ['crypto', 'fs', 'path', 'child_process', 'https', 'http', 'zlib', 'dns', 'tls'].map(requireBuiltin);
const { X509Certificate } = crypto;
const { pipeline } = requireBuiltin('stream').promises;
const SCRIPT_PATH = path.resolve(process.argv[1]), BASE_DIR = path.dirname(SCRIPT_PATH);
loadEnv(path.join(BASE_DIR, '.env'));

const getEnv = (key, defaultValue = '') => (process.env[key] ?? defaultValue).trim();
const getEnvMode = (key, defaultValue = '') => getEnv(key, defaultValue).toLowerCase();

// ========== 用户配置(优先级：环境变量 > 同目录 .env > 默认值) ==========
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
if (CONFIG.LOG_LEVEL !== 'none') persistEnv(path.join(BASE_DIR, '.env'));
const { NAME, UUID, CLOUDFLARE_TUNNEL_TOKEN, CLOUDFLARE_IP, PORT, VLESS_MODE, VMESS_MODE, TROJAN_MODE, SHADOWSOCKS_MODE,
  HYSTERIA2_MODE, MIXED_MODE, WIREGUARD_MODE, CERT_HOST, KOMARI_ENDPOINT, KOMARI_TOKEN, LOG_LEVEL } = CONFIG;

const QUIET = LOG_LEVEL === 'none';
if (QUIET) console.log = console.error = () => {};
const STDIO = QUIET ? 'ignore' : 'inherit';
const uuidHash = crypto.createHash('sha256').update(UUID).digest('hex');
const uuidHashPrefix = uuidHash.slice(0, 4);
const ARCH = { x64: 'amd64', arm64: 'arm64' }[process.arch];

console.log('[ENV]', Object.entries(CONFIG).filter(([, value]) => value).map(([key, value]) => `${key}=${/UUID|TOKEN/.test(key) ? `${value.slice(0, 4)}***` : value}`).join(' '));

let WORK_DIR = '';
for (const dir of [...(CONFIG.WORK_DIR ? [path.resolve(BASE_DIR, CONFIG.WORK_DIR)] : []), `/var/lib/.cache${uuidHashPrefix}`, `/tmp/.cache${uuidHashPrefix}`]) {
  try { fs.mkdirSync(dir, { recursive: true }); fs.accessSync(dir, fs.constants.R_OK | fs.constants.W_OK); WORK_DIR = dir; break; }
  catch (error) { console.error(`[DIR] Cannot access ${dir}: ${error.message}`); }
}
if (!WORK_DIR) process.exit(1);
console.log(`[DIR] Work directory: ${WORK_DIR}`);
process.chdir(WORK_DIR);
if (!ARCH) die(`[ARCH] Unsupported architecture: ${process.arch}`);

// ========== 通用函数 ==========
function die(message) { console.error(message); process.exit(1); }
function readLog(filePath) { try { return fs.readFileSync(filePath, 'utf8'); } catch { return ''; } }
function loadEnv(filePath) {
  try { return process.loadEnvFile(filePath); } catch (error) { if (error.code === 'ENOENT') return; }
  for (const line of readLog(filePath).split(/\r?\n/)) {
    const match = line.match(/^\s*(?:export\s+)?([A-Za-z_]\w*)\s*=\s*(.*)$/);
    if (!match || line.trim().startsWith('#')) continue;
    const rawValue = match[2].trim(), quoted = rawValue.match(/^(['"])(.*?)\1/);
    if (process.env[match[1]] === undefined) process.env[match[1]] = quoted ? quoted[2] : rawValue.replace(/\s+#.*$/, '');
  }
}
function normalizeConfig() {
  CONFIG.UUID = CONFIG.UUID || crypto.randomUUID();
  CONFIG.PORT = CONFIG.PORT.replace(/^0+$/, '');
  CONFIG.CERT_HOST = CONFIG.CERT_HOST.replace(/^[a-z]+:\/\//i, '').replace(/[/:].*$/, '');
}
// 把配置持久化到 .env(权限 600)，并把脚本中的 CONFIG 改为只读环境变量
function persistEnv(filePath) {
  const formatEnvLine = (key, value) => `${key}=${/[\s#'"]/.test(value) ? `"${value}"` : value}`;
  let fileText = readLog(filePath);
  for (const [key, value] of Object.entries(CONFIG)) {
    const keyPattern = new RegExp(`^\\s*(?:export\\s+)?${key}\\s*=.*$`, 'm');
    fileText = keyPattern.test(fileText)
      ? fileText.replace(keyPattern, () => formatEnvLine(key, value))
      : `${fileText}${fileText && !fileText.endsWith('\n') ? '\n' : ''}${formatEnvLine(key, value)}\n`;
  }
  try { fs.writeFileSync(filePath, fileText, { mode: 0o600 }); fs.chmodSync(filePath, 0o600); }
  catch (error) { console.error(`[ENV] Cannot write ${filePath}: ${error.message}`); }
  rewriteConfigToEnvReads();
}
function rewriteConfigToEnvReads() {
  try {
    const scriptSource = fs.readFileSync(SCRIPT_PATH, 'utf8');
    const configBlock = scriptSource.match(/^const CONFIG = \{\n[\s\S]*?\n\};/m);
    if (!configBlock) return console.error('[ENV] CONFIG block not found, script not rewritten');
    const rewrittenBlock = configBlock[0].replace(/^  ([A-Z0-9_]+): .*$/gm, (line, key) => (key in CONFIG
      ? `  ${key}: ${/_MODE$|^LOG_LEVEL$/.test(key) ? 'getEnvMode' : 'getEnv'}('${key}'),`
      : line));
    fs.writeFileSync(SCRIPT_PATH, scriptSource.replace(configBlock[0], () => rewrittenBlock));
  } catch (error) { console.error(`[ENV] Cannot rewrite script: ${error.message}`); }
}

const toBase64 = (data) => Buffer.from(data).toString('base64');
const sleep = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds));
const validPort = (value) => /^\d+$/.test(value) && +value >= 1 && +value <= 65535;
const nonEmpty = (filePath) => { try { return fs.statSync(filePath).size > 0; } catch { return false; } };
const urlEncode = (text) => encodeURIComponent(text).replace(/[!'()*]/g, (char) => `%${char.charCodeAt(0).toString(16).toUpperCase()}`);

// HTTPS 请求：跟随重定向；传 outputFile 则写入文件，否则返回 { status, body }
function request(url, { family, timeout = 10000, outputFile, redirects = 5 } = {}) {
  return new Promise((resolve, reject) => {
    const httpRequest = https.get(url, { family }, (response) => {
      const { statusCode, headers } = response;
      if ([301, 302, 303, 307, 308].includes(statusCode) && headers.location) {
        response.resume();
        return redirects <= 0 ? reject(new Error('too many redirects'))
          : request(new URL(headers.location, url).href, { family, timeout, outputFile, redirects: redirects - 1 }).then(resolve, reject);
      }
      if (outputFile) {
        if (statusCode >= 400) { response.resume(); return reject(new Error(`HTTP ${statusCode}`)); }
        return response.pipe(fs.createWriteStream(outputFile).on('finish', () => resolve({ status: statusCode })).on('error', reject));
      }
      const chunks = [];
      response.on('data', (chunk) => chunks.push(chunk))
        .on('end', () => resolve({ status: statusCode, body: Buffer.concat(chunks).toString() }))
        .on('error', reject);
    });
    httpRequest.setTimeout(timeout, () => httpRequest.destroy(new Error('timeout')));
    httpRequest.on('error', reject);
  });
}

// 先写 .part 再改名，失败重试 3 次
async function download(destPath, url) {
  let lastError;
  for (let attempt = 0; attempt < 3; attempt++) {
    try { await request(url, { outputFile: `${destPath}.part` }); fs.renameSync(`${destPath}.part`, destPath); return true; }
    catch (error) { lastError = error; fs.rmSync(`${destPath}.part`, { force: true }); await sleep(1000); }
  }
  console.error(`[DL] Download failed: ${url} (${lastError?.code ?? ''} ${lastError?.message ?? 'unknown error'})`);
  return false;
}

// 流式解压 zip：只读中央目录，逐文件解压
async function unzip(zipPath, targetDir) {
  const rootDir = path.resolve(targetDir), zipFd = fs.openSync(zipPath, 'r'), zipSize = fs.fstatSync(zipFd).size;
  const readAt = (length, position) => { const buffer = Buffer.alloc(length); fs.readSync(zipFd, buffer, 0, length, position); return buffer; };
  try {
    const tail = readAt(Math.min(zipSize, 65557), Math.max(0, zipSize - 65557));
    let eocdOffset = tail.length - 22;
    while (eocdOffset >= 0 && tail.readUInt32LE(eocdOffset) !== 0x06054b50) eocdOffset--;
    if (eocdOffset < 0) throw new Error('not a zip file');
    const centralDirectory = readAt(tail.readUInt32LE(eocdOffset + 12), tail.readUInt32LE(eocdOffset + 16));
    for (let entryIndex = 0, cursor = 0; entryIndex < tail.readUInt16LE(eocdOffset + 10); entryIndex++) {
      const method = centralDirectory.readUInt16LE(cursor + 10), compressedSize = centralDirectory.readUInt32LE(cursor + 20);
      const nameLength = centralDirectory.readUInt16LE(cursor + 28), localHeaderOffset = centralDirectory.readUInt32LE(cursor + 42);
      const entryName = centralDirectory.toString('utf8', cursor + 46, cursor + 46 + nameLength);
      cursor += 46 + nameLength + centralDirectory.readUInt16LE(cursor + 30) + centralDirectory.readUInt16LE(cursor + 32);
      const entryPath = path.resolve(rootDir, entryName);
      if (entryName.endsWith('/') || !entryPath.startsWith(rootDir + path.sep)) continue;
      fs.mkdirSync(path.dirname(entryPath), { recursive: true });
      if (!compressedSize) { fs.writeFileSync(entryPath, ''); continue; }
      const localHeader = readAt(30, localHeaderOffset);
      const dataStart = localHeaderOffset + 30 + localHeader.readUInt16LE(26) + localHeader.readUInt16LE(28);
      await pipeline(fs.createReadStream(zipPath, { start: dataStart, end: dataStart + compressedSize - 1 }),
        ...(method === 0 ? [] : [zlib.createInflateRaw()]), fs.createWriteStream(entryPath));
    }
  } finally { fs.closeSync(zipFd); }
}

// Go 程序内存参数：GOGC 调低；有容器内存限制时设 GOMEMLIMIT
const GO_ENV = (() => {
  const memoryLimit = +(readLog('/sys/fs/cgroup/memory.max').trim() || readLog('/sys/fs/cgroup/memory/memory.limit_in_bytes').trim());
  return { GOGC: '50', ...(memoryLimit > 0 && memoryLimit < 2 ** 40 ? { GOMEMLIMIT: `${Math.floor(memoryLimit * 0.6 / 1048576)}MiB` } : {}) };
})();

const childProcesses = [];
process.on('exit', () => childProcesses.forEach((child) => { try { child.kill(); } catch {} }));
for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, () => process.exit(0));

async function killPrevious(processName, logTag) {
  try { childProcess.execFileSync('pkill', ['-x', processName], { stdio: 'ignore' }); } catch { return; }
  console.log(`[${logTag}] Stopped previous ${processName}`);
  await sleep(1000);
}

function spawnBackground(binPath, args, logFile, extraEnv = {}) {
  const logFd = fs.openSync(logFile, 'w');
  const child = childProcess.spawn(binPath, args, { env: { ...process.env, ...GO_ENV, ...extraEnv }, stdio: ['ignore', logFd, logFd] });
  fs.closeSync(logFd);
  childProcesses.push(child);
  return child;
}

// ========== 协议与模式 ==========
const PROTOCOLS = ['vless', 'vmess', 'trojan', 'shadowsocks'];
const WS_PATH = Object.fromEntries(PROTOCOLS.map((protocol) => [protocol, `/${UUID}-${protocol === 'shadowsocks' ? 'ss' : protocol}`]));
const SS_PORT = 40004, SS_WS_PORT = 40005;
const abstractSocket = (name) => `@xray-${crypto.createHash('sha1').update(BASE_DIR).digest('hex').slice(0, 8)}-${name}`;
const endpointOf = (protocol, name, ssPort) => (protocol === 'shadowsocks'
  ? { listen: '127.0.0.1', port: ssPort, dest: ssPort }
  : { listen: abstractSocket(name), dest: abstractSocket(name) });
const internalEndpoint = (protocol) => endpointOf(protocol, protocol, SS_PORT);
const wsInternalEndpoint = (protocol) => endpointOf(protocol, `${protocol}-ws`, SS_WS_PORT);
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

const modePort = (envName, value, description) => {
  if (!value) return 0;
  if (!validPort(value)) die(`[MODE] ${envName}='${value}' is invalid (expected a port 1-65535, or empty to disable)`);
  console.log(`[MODE] port ${+value}/${description}`);
  return +value;
};
const HYSTERIA2_PORT = modePort('HYSTERIA2_MODE', HYSTERIA2_MODE, 'udp: hysteria2');
const MIXED_PORT = modePort('MIXED_MODE', MIXED_MODE, 'tcp: mixed (socks5 + http)');
const WIREGUARD_PORT = modePort('WIREGUARD_MODE', WIREGUARD_MODE, 'udp: wireguard');

// 1. 解析各协议的 *_MODE
function parseModes() {
  for (const protocol of PROTOCOLS) {
    const envName = `${protocol.toUpperCase()}_MODE`;
    let hasReality = false;
    for (const token of (MODES[protocol] || '').split(',').map((segment) => segment.trim()).filter(Boolean)) {
      if (token === 'ws' || token === 'cloudflare') {
        const protocolList = token === 'ws' ? WS_PROTOCOLS : CF_PROTOCOLS;
        if (protocolList.includes(protocol)) die(`[MODE] ${envName}: '${token}' is given more than once`);
        protocolList.push(protocol);
        if (token === 'ws') HAS_WS = true; else HAS_CF = true;
        continue;
      }
      if (hasReality) die(`[MODE] ${envName}: only one Reality entry (a port or a fallback protocol) is allowed`);
      hasReality = true;
      if (/^\d+$/.test(token)) {
        if (!validPort(token)) die(`[MODE] ${envName}='${token}': port must be 1-65535`);
        NUMERIC_PORT[protocol] = +token;
      } else if (/^[a-z]+$/.test(token)) {
        if (!PROTOCOLS.includes(token)) die(`[MODE] ${envName}='${token}' is not valid`);
        if (token === protocol) die(`[MODE] ${envName}='${token}': a protocol cannot fall back to itself`);
        if (!['vless', 'trojan'].includes(protocol)) die(`[MODE] ${envName}='${token}': only VLESS and TROJAN can choose a fallback`);
        FALLBACK[protocol] = token;
      } else die(`[MODE] ${envName}='${token}' is invalid`);
    }
  }
  QUICK_TUNNEL = HAS_CF && CLOUDFLARE_TUNNEL_TOKEN === 'try';
}

// 2. 整理回落关系为 Reality 链
function buildChains() {
  for (let changed = true; changed;) {
    changed = false;
    for (const [protocol, target] of Object.entries(FALLBACK)) {
      if (NUMERIC_PORT[target] || FALLBACK[target]) continue;
      console.log(`[MODE] ${protocol.toUpperCase()}_MODE='${target}': ${target.toUpperCase()} has no Reality port, so this fallback entry is ignored`);
      delete FALLBACK[protocol];
      changed = true;
    }
  }
  for (const [protocol, target] of Object.entries(FALLBACK)) {
    if (FALLBACK_PARENT[target]) die(`[MODE] ${target.toUpperCase()} is the fallback of both ${FALLBACK_PARENT[target].toUpperCase()} and ${protocol.toUpperCase()}, it can only have one`);
    FALLBACK_PARENT[target] = protocol;
  }
  for (const protocol of PROTOCOLS) {
    const hasReality = !!(NUMERIC_PORT[protocol] || FALLBACK[protocol]);
    if (FRONT_PROTOCOLS().includes(protocol) || hasReality || FALLBACK_PARENT[protocol]) ENABLED.push(protocol);
    if (hasReality && !FALLBACK_PARENT[protocol]) CHAIN_HEADS.push(protocol);
  }
  for (const head of CHAIN_HEADS) {
    let tail = head;
    CHAIN[head] = [head];
    while (FALLBACK[tail]) { tail = FALLBACK[tail]; CHAIN[head].push(tail); }
    HEAD_PORT[head] = NUMERIC_PORT[tail];
    for (const protocol of CHAIN[head]) REALITY_PORT[protocol] = HEAD_PORT[head];
  }
  XRAY_ON = ENABLED.length > 0 || !!(HYSTERIA2_PORT || MIXED_PORT || WIREGUARD_PORT);
  for (const protocol of ENABLED) {
    if ((NUMERIC_PORT[protocol] || FALLBACK[protocol] || FALLBACK_PARENT[protocol]) && !REALITY_PORT[protocol]) die(`[MODE] ${protocol.toUpperCase()} is part of a fallback loop`);
  }
}

// 3. 前置入口规划
function planFront() {
  WS_FRONT_ON = HAS_WS || (!!PORT && !HAS_CF);
  CF_FRONT_ON = HAS_CF;
  if (WS_FRONT_ON) {
    if (PORT && !validPort(PORT)) die(`[MODE] PORT='${PORT}' is not a valid port`);
    FRONT_PORT = +(PORT || DEFAULT_FRONT_PORT);
    if (PORT && CHAIN_HEADS.some((head) => HEAD_PORT[head] === FRONT_PORT)) SHARE_FRONT = true;
  }
}

// 4. 端口检查
function checkPorts() {
  const usedPorts = CHAIN_HEADS.map((head) => HEAD_PORT[head]);
  if (WS_FRONT_ON && !SHARE_FRONT) usedPorts.push(FRONT_PORT);
  if (CF_FRONT_ON && CF_PORT) usedPorts.push(CF_PORT);
  if (MIXED_PORT) usedPorts.push(MIXED_PORT);
  const duplicatePort = usedPorts.find((port, index) => usedPorts.indexOf(port) !== index);
  if (duplicatePort !== undefined) die(`[MODE] Port ${duplicatePort} is used more than once`);
  const conflictingPort = usedPorts.find((port) => port === SS_PORT || port === SS_WS_PORT);
  if (conflictingPort !== undefined) die(`[MODE] Port ${conflictingPort} conflicts with the internal ports 40004 / 40005 used by Shadowsocks`);
}

// ========== TLS 证书 ==========
const IPV4 = /^\d{1,3}(\.\d{1,3}){3}$/;
let CERT_FILE = '', KEY_FILE = '', TLS_SERVER_NAME = '', TLS_INSECURE = true, TLS_PINNED_CERT_SHA256 = '';

// 自签证书(RSA 2048，10 年)；已有且 30 天内不过期则复用
function generateSelfSignedCert(commonName) {
  const certDir = path.join(WORK_DIR, '.selfsigned');
  fs.mkdirSync(certDir, { recursive: true, mode: 0o700 });
  CERT_FILE = path.join(certDir, `${commonName}.crt`);
  KEY_FILE = path.join(certDir, `${commonName}.key`);
  if (nonEmpty(CERT_FILE) && nonEmpty(KEY_FILE)) {
    try { if (Date.parse(new X509Certificate(fs.readFileSync(CERT_FILE)).validTo) - Date.now() > 30 * 86400e3) return; } catch {}
  }
  childProcess.execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '3650',
    '-keyout', KEY_FILE, '-out', CERT_FILE, '-subj', `/CN=${commonName}`, '-addext', `subjectAltName=DNS:${commonName},DNS:localhost`], { stdio: 'ignore' });
  fs.chmodSync(KEY_FILE, 0o600);
}

// 校验证书链：域名匹配、逐级验签、最终落在系统信任根上；返回空串表示可信
function verifyChain(certChain, hostname) {
  if (!certChain[0].checkHost(hostname)) return 'hostname mismatch';
  const trustedRoots = (tls.getCACertificates ? tls.getCACertificates('default') : tls.rootCertificates).map((pem) => new X509Certificate(pem));
  const now = Date.now();
  const isValidNow = (cert) => now >= Date.parse(cert.validFrom) && now <= Date.parse(cert.validTo);
  const isSignedBy = (cert, issuer) => cert.checkIssued(issuer) && cert.verify(issuer.publicKey);
  let current = certChain[0];
  for (let depth = 0; depth < 8; depth++) {
    if (!isValidNow(current)) return 'certificate expired or not yet valid';
    if (trustedRoots.some((root) => root.fingerprint256 === current.fingerprint256 || (isValidNow(root) && isSignedBy(current, root)))) return '';
    current = certChain.slice(1).find((issuer) => issuer !== current && issuer.ca && isSignedBy(current, issuer));
    if (!current) return 'issuer is not trusted';
  }
  return 'chain too long';
}

function trustedCertForHost(hostname) {
  const certFile = path.join(WORK_DIR, `${hostname}.crt`), keyFile = path.join(WORK_DIR, `${hostname}.key`);
  if (!nonEmpty(certFile) || !nonEmpty(keyFile)) return false;
  let certChain;
  try {
    certChain = (fs.readFileSync(certFile, 'utf8').match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g) || [])
      .map((pem) => new X509Certificate(pem));
    if (!certChain.length || !certChain[0].checkPrivateKey(crypto.createPrivateKey(fs.readFileSync(keyFile)))) throw new Error('no matching certificate and key');
  } catch (error) { console.error(`[TLS] Cannot read ${certFile} / ${keyFile}: ${error.message}`); return false; }
  const reason = verifyChain(certChain, hostname);
  if (reason) { console.error(`[TLS] ${certFile} is not trusted for ${hostname}: ${reason}`); return false; }
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
  const privateKeyBytes = crypto.createHash('sha256').update(`${label}:${UUID}`).digest();
  privateKeyBytes[0] &= 248;
  privateKeyBytes[31] = (privateKeyBytes[31] & 127) | 64;
  const publicKeyBytes = crypto.createPublicKey(crypto.createPrivateKey({
    key: Buffer.concat([Buffer.from('302e020100300506032b656e04220420', 'hex'), privateKeyBytes]), format: 'der', type: 'pkcs8',
  })).export({ type: 'spki', format: 'der' }).subarray(-32);
  return [privateKeyBytes.toString(encoding), Buffer.from(publicKeyBytes).toString(encoding)];
}

// ========== 链接地址 ==========
let PUBLIC_ADDRESS = '';
const TRACE_URL = 'https://one.one.one.one/cdn-cgi/trace';

async function resolvePublicAddress() {
  if (IPV4.test(CERT_HOST)) PUBLIC_ADDRESS = CERT_HOST;
  else {
    const traceResponse = await request(TRACE_URL, { family: 4, timeout: 5000 }).catch(() => null);
    PUBLIC_ADDRESS = ((traceResponse && traceResponse.body.match(/^ip=(.*)$/m)) || [, ''])[1].trim();
    if (CERT_HOST && PUBLIC_ADDRESS) {
      const resolvedIps = await dns.promises.lookup(CERT_HOST, { family: 4, all: true })
        .then((entries) => entries.map((entry) => entry.address))
        .catch(() => []);
      if (resolvedIps.includes(PUBLIC_ADDRESS)) {
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
const streamWs = (wsPath) => ({ network: 'ws', security: 'none', wsSettings: { path: wsPath } });
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

function protocolSettings(protocol, fallbacks, flow) {
  const fallbackConfig = fallbacks ? { fallbacks } : {};
  switch (protocol) {
    case 'vless': return { clients: [{ id: UUID, email: UUID, ...(flow ? { flow } : {}) }], decryption: 'none', ...fallbackConfig };
    case 'vmess': return { clients: [{ id: UUID, email: UUID }] };
    case 'trojan': return { clients: [{ password: UUID, email: UUID }], ...fallbackConfig };
    case 'shadowsocks': return { method: 'aes-256-gcm', password: UUID, network: 'tcp' };
  }
}

function buildConfig() {
  const inbounds = [];
  for (const protocol of FRONT_PROTOCOLS()) {
    const endpoint = wsInternalEndpoint(protocol);
    inbounds.push(inbound(`${protocol}-ws-in`, endpoint.listen, endpoint.port, protocol, protocolSettings(protocol), streamWs(WS_PATH[protocol])));
  }
  const frontFallbacks = (protocols) => [
    ...protocols.map((protocol) => ({ path: WS_PATH[protocol], dest: wsInternalEndpoint(protocol).dest, xver: 0 })),
    { dest: WEB_SOCKET, xver: 0 },
  ];
  if (WS_FRONT_ON) {
    const [listen, port] = SHARE_FRONT ? [FRONT_SOCKET, undefined] : ['::', FRONT_PORT];
    inbounds.push(inbound('front-in', listen, port, 'vless', protocolSettings('vless', frontFallbacks(WS_PROTOCOLS)), FRONT_TLS ? streamTls('tcp', 'http/1.1') : streamTcp()));
  }
  if (CF_FRONT_ON) inbounds.push(inbound('cf-front-in', '::', CF_PORT, 'vless', protocolSettings('vless', frontFallbacks(CF_PROTOCOLS)), streamTcp()));
  for (const head of CHAIN_HEADS) {
    for (const protocol of CHAIN[head]) {
      const fallbacks = FALLBACK[protocol] ? [{ dest: internalEndpoint(FALLBACK[protocol]).dest, xver: 0 }] : undefined;
      if (protocol !== head) {
        const endpoint = internalEndpoint(protocol);
        inbounds.push(inbound(`${protocol}-in`, endpoint.listen, endpoint.port, protocol, protocolSettings(protocol, fallbacks), streamTcp()));
        continue;
      }
      const streamSettings = SHARE_FRONT && HEAD_PORT[head] === FRONT_PORT
        ? streamReality(FRONT_SOCKET, TLS_SERVER_NAME)
        : streamReality();
      inbounds.push(inbound(`${protocol}-in`, '::', HEAD_PORT[head], protocol,
        protocolSettings(protocol, fallbacks, protocol === 'vless' ? VLESS_FLOW : ''), streamSettings));
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

function realityLink(protocol, port, name) {
  const serverName = SHARE_FRONT && port === FRONT_PORT ? TLS_SERVER_NAME : 'www.iij.ad.jp';
  const encryptionPrefix = protocol === 'vless'
    ? `encryption=none${VLESS_FLOW ? `&flow=${VLESS_FLOW}` : ''}&`
    : protocol === 'vmess' ? 'encryption=auto&' : '';
  const query = `security=reality&sni=${serverName}&fp=chrome&pbk=${REALITY_PUBLIC_KEY}&type=tcp&sid=${REALITY_SHORT_ID}`;
  const userinfo = protocol === 'shadowsocks' ? SS_USERINFO : UUID;
  return `${protocol === 'shadowsocks' ? 'ss' : protocol}://${userinfo}@${PUBLIC_ADDRESS}:${port}?${encryptionPrefix}${query}#${urlEncode(name)}`;
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

function wsLink(protocol, params, name) {
  const wsPath = WS_PATH[protocol], encodedName = urlEncode(name);
  const query = `sni=${params.host}&fp=chrome&type=ws&host=${params.host}&path=${wsPath.replace(/\//g, '%2F')}${params.query}#${encodedName}`;
  switch (protocol) {
    case 'vless': return `vless://${UUID}@${params.address}:${params.port}?encryption=none&security=tls&${query}`;
    case 'trojan': return `trojan://${UUID}@${params.address}:${params.port}?security=tls&${query}`;
    case 'vmess': return `vmess://${toBase64(JSON.stringify({
      v: '2', ps: name, add: params.address, port: String(params.port), id: UUID, aid: '0', scy: 'none', net: 'ws', type: 'none',
      host: params.host, path: wsPath + (params.mode === 'cloudflare' ? '?ed=2560' : ''), tls: 'tls', sni: params.host, alpn: '', fp: '',
      insecure: String(params.insecure), ...(params.extra || {}), vcn: '', pcs: params.pinned,
    }))}`;
    case 'shadowsocks': {
      if (params.mode === 'ws' && TLS_INSECURE) {
        console.error('[MODE] ws mode: Shadowsocks (v2ray-plugin) needs a trusted certificate, no SS link generated');
        return '';
      }
      const plugin = `v2ray-plugin;tls;host=${params.host};path=${wsPath};mux=0`.replace(/;/g, '%3B').replace(/=/g, '%3D').replace(/\//g, '%2F');
      return `ss://${SS_USERINFO}@${params.address}:${params.port}/?plugin=${plugin}#${encodedName}`;
    }
  }
}

const realityNodes = () => ENABLED.filter((protocol) => REALITY_PORT[protocol])
  .map((protocol) => realityLink(protocol, REALITY_PORT[protocol], NAME));
const wsNodes = (params) => ENABLED.filter((protocol) => WS_PROTOCOLS.includes(protocol))
  .map((protocol) => wsLink(protocol, params, (REALITY_PORT[protocol] || CF_PROTOCOLS.includes(protocol)) ? `${NAME}-ws` : NAME));
const cloudflareNodes = (params) => ENABLED.filter((protocol) => CF_PROTOCOLS.includes(protocol))
  .map((protocol) => wsLink(protocol, params, NAME));
const hysteria2Link = () => `hysteria2://${UUID}@${PUBLIC_ADDRESS}:${HYSTERIA2_PORT}/?sni=${TLS_SERVER_NAME}${TLS_INSECURE ? '&insecure=1' : ''}#${ENCODED_NAME}`;
const mixedLinks = () => ['socks5', 'http'].map((scheme) => `${scheme}://${UUID}:${UUID}@${PUBLIC_ADDRESS}:${MIXED_PORT}#${ENCODED_NAME}`).join('\n');
const wireguardLink = () => `wireguard://${urlEncode(WG_CLIENT_PRIV)}@${PUBLIC_ADDRESS}:${WIREGUARD_PORT}?publickey=${urlEncode(WG_SERVER_PUB)}&address=${urlEncode(WG_CLIENT_ADDR)}&mtu=1420#${ENCODED_NAME}`;
const wireguardConfig = () => `[Interface]\nPrivateKey = ${WG_CLIENT_PRIV}\nAddress = ${WG_CLIENT_ADDR}\nDNS = 1.1.1.1\nMTU = 1420\n\n[Peer]\nPublicKey = ${WG_SERVER_PUB}\nEndpoint = ${PUBLIC_ADDRESS}:${WIREGUARD_PORT}\nAllowedIPs = 0.0.0.0/0, ::/0\nPersistentKeepalive = 25\n`;

// ========== 内置 HTTP 服务(订阅 + 回落) ==========
function startWeb(subscriptionBody) {
  const [destHost, destPort] = WEB_DESTINATION.split(':');
  http.createServer((incoming, response) => {
    const pathname = incoming.url.split('?')[0];
    console.log(`[WEB] ${incoming.method} ${pathname === `/${UUID}` ? '/UUID' : pathname}`);
    if ((incoming.method === 'GET' || incoming.method === 'HEAD') && pathname === `/${UUID}`) {
      response.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store' });
      return response.end(incoming.method === 'HEAD' ? undefined : subscriptionBody);
    }
    if (!WEB_DESTINATION) { response.writeHead(404, { 'Content-Type': 'text/plain' }); return response.end('Not Found'); }
    const upstream = http.request({ host: destHost, port: +destPort, path: incoming.url, method: incoming.method, headers: incoming.headers }, (upstreamResponse) => {
      response.writeHead(upstreamResponse.statusCode, upstreamResponse.headers);
      upstreamResponse.pipe(response);
    });
    upstream.on('error', () => { response.writeHead(502); response.end(); });
    incoming.pipe(upstream);
  }).on('error', (error) => console.error(`[WEB] HTTP service failed: ${error.message}`))
    .listen(`\0${WEB_SOCKET.slice(1)}`);
}

// ========== 外部程序 ==========
async function fetchBinary(fileName, url) {
  const binPath = path.join(WORK_DIR, fileName);
  if (!await download(binPath, url)) process.exit(1);
  fs.chmodSync(binPath, 0o755);
  return binPath;
}

async function startKomari() {
  const serviceName = `svc-k${uuidHashPrefix}`;
  await killPrevious(serviceName, 'KOMARI');
  const binPath = await fetchBinary(serviceName, `https://github.com/komari-monitor/komari-agent/releases/latest/download/komari-agent-linux-${ARCH}`);
  const agentEnv = { AGENT_ENDPOINT: KOMARI_ENDPOINT, AGENT_TOKEN: KOMARI_TOKEN };
  if (XRAY_ON) {
    spawnBackground(binPath, [], QUIET ? '/dev/null' : path.join(WORK_DIR, `${serviceName}.log`), agentEnv);
    return console.log(`[KOMARI] Agent started, reporting to ${KOMARI_ENDPOINT}`);
  }
  console.log(`[KOMARI] No proxy protocol enabled, running the agent only, reporting to ${KOMARI_ENDPOINT}`);
  const child = childProcess.spawn(binPath, [], { env: { ...process.env, ...GO_ENV, ...agentEnv }, stdio: STDIO });
  childProcesses.push(child);
  child.on('exit', (code) => process.exit(code ?? 1));
  await new Promise(() => {});
}

// 从 cloudflared 日志取第一条有具体域名、Service 为 http://localhost:端口 的 ingress 规则
function parseIngress(logText) {
  const configMatch = logText.split('\n')
    .filter((line) => line.includes('Updated to new configuration'))
    .pop()?.match(/config="(.*)" version=/);
  if (!configMatch) return null;
  let config;
  try { config = JSON.parse(configMatch[1].replace(/\\"/g, '"')); } catch { return null; }
  for (const rule of config.ingress || []) {
    const serviceMatch = rule.hostname && !rule.hostname.includes('*')
      && /^http:\/\/(?:localhost|127\.0\.0\.1):(\d+)$/.exec(rule.service || '');
    if (serviceMatch) return { hostname: rule.hostname, port: serviceMatch[1] };
  }
  return null;
}

async function startCloudflared() {
  const serviceName = `svc-c${uuidHashPrefix}`;
  await killPrevious(serviceName, 'CF');
  const binPath = await fetchBinary(serviceName, `https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-${ARCH}`);
  const logFile = path.join(WORK_DIR, `${serviceName}.log`);
  const fail = (message) => { console.error(`[CF] ${message}`); process.exit(1); };
  childProcess.spawnSync(binPath, ['--version'], { stdio: STDIO });

  if (QUICK_TUNNEL) {
    CF_PORT = DEFAULT_FRONT_PORT;
    checkPorts();
    spawnBackground(binPath, ['--no-autoupdate', 'tunnel', '--url', `http://localhost:${CF_PORT}`], logFile);
    for (let attempt = 0; attempt < 30 && !CF_HOSTNAME; attempt++) {
      CF_HOSTNAME = [...readLog(logFile).matchAll(/https:\/\/([a-z0-9-]+\.trycloudflare\.com)/g)]
        .map((match) => match[1])
        .find((host) => !host.startsWith('api.')) || '';
      if (!CF_HOSTNAME) await sleep(1000);
    }
    if (!CF_HOSTNAME) fail(`Cannot find the trycloudflare.com hostname in ${logFile}, exiting`);
    console.log(`[CF] Quick tunnel hostname: ${CF_HOSTNAME} (service port=${CF_PORT})`);
  } else {
    spawnBackground(binPath, ['--no-autoupdate', 'tunnel', 'run'], logFile, { TUNNEL_TOKEN: CLOUDFLARE_TUNNEL_TOKEN });
    for (let attempt = 0; attempt < 30 && !readLog(logFile).includes('Updated to new configuration'); attempt++) await sleep(1000);
    const ingressRule = parseIngress(readLog(logFile));
    if (!ingressRule || !validPort(ingressRule.port)) {
      fail(`Cannot read hostname / port from ${logFile} (needs a Public hostname without * and a Service like http://localhost:PORT), exiting`);
    }
    CF_HOSTNAME = ingressRule.hostname;
    CF_PORT = +ingressRule.port;
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
  const xrayBinPath = path.join(WORK_DIR, `xray-${uuidHashPrefix}`);
  const extractedBinPath = path.join(WORK_DIR, 'xray');
  const configFile = path.join(WORK_DIR, 'config.json'), zipFile = path.join(WORK_DIR, 'xray.zip');
  await killPrevious(`xray-${uuidHashPrefix}`, 'XRAY');
  if (!await download(zipFile, `https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-${ARCH === 'amd64' ? '64' : 'arm64-v8a'}.zip`)) process.exit(1);
  await unzip(zipFile, WORK_DIR);
  fs.rmSync(zipFile, { force: true });
  try { fs.renameSync(extractedBinPath, xrayBinPath); } catch (error) { console.error(`[XRAY] Cannot rename binary: ${error.message}`); }
  if (!nonEmpty(xrayBinPath)) { console.error(`[XRAY] Binary not found after extraction: ${xrayBinPath}`); process.exit(1); }
  fs.chmodSync(xrayBinPath, 0o755);
  const xrayEnv = { ...process.env, ...GO_ENV, XRAY_LOCATION_ASSET: WORK_DIR };
  const runXray = (args) => childProcess.spawnSync(xrayBinPath, args, { stdio: STDIO, env: xrayEnv });
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
  const allNodes = nodes.filter(Boolean).map((node) => `${node}\n`).join('');
  console.log(`\n=== Nodes ===\n${allNodes}\n=== Subscription (base64) ===\n${toBase64(allNodes)}\n`);
  if (WIREGUARD_PORT) console.log(`\n=== WireGuard config (wg-quick) ===\n${wireguardConfig()}`);
  if (WS_FRONT_ON || CF_FRONT_ON) {
    startWeb(toBase64(allNodes));
    const bases = [
      ...(CF_FRONT_ON && CF_HOSTNAME ? [`https://${CF_HOSTNAME}`] : []),
      ...(WS_FRONT_ON ? [`${FRONT_TLS ? 'https' : 'http'}://${PUBLIC_ADDRESS}:${FRONT_PORT}`] : []),
    ];
    if (bases.length) console.log(`\n=== Subscription URL ===\n${bases.map((base) => `${base}/${UUID}`).join('\n')}${FRONT_TLS && TLS_INSECURE ? '\n(自签证书：客户端需要允许不校验证书)' : ''}\n`);
  }

  // ---- systemd 服务文件 ----
  const serviceName = `cache-${uuidHash.slice(0, 6)}`;
  const serviceFilePath = path.join(WORK_DIR, `${serviceName}.service`);
  fs.writeFileSync(serviceFilePath, `[Unit]\nDescription=${serviceName}\nAfter=network.target\n\n[Service]\nType=simple\nRestart=always\nRestartSec=5\nWorkingDirectory=${WORK_DIR}\nExecStart=${process.execPath} ${SCRIPT_PATH}\nKillMode=mixed\nKillSignal=SIGTERM\n\n[Install]\nWantedBy=multi-user.target\n`);
  console.log(`\n=== systemd service (${serviceName}) ===\ncp ${serviceFilePath} /etc/systemd/system/${serviceName}.service\nsystemctl daemon-reload && systemctl enable --now ${serviceName}`);

  try { requireBuiltin('v8').setFlagsFromString('--expose-gc'); requireBuiltin('vm').runInNewContext('gc')(); } catch {}
  const xrayProcess = childProcess.spawn(xrayBinPath, ['run', '-c', configFile], { stdio: STDIO, env: xrayEnv });
  childProcesses.push(xrayProcess);
  xrayProcess.on('exit', (code) => process.exit(code ?? 1));
}

main().catch((error) => { console.error(error); process.exit(1); });
