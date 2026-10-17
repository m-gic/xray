#!/usr/bin/env node
'use strict';
// 纯 Node.js(>=16)，仅内置模块。每个 *_MODE 可逗号分隔：一个前置模式 ws/cloudflare + 一个 Reality 项(端口或回落协议名)
const requireBuiltin = (moduleName) => (typeof require === 'function' ? require(moduleName) : process.getBuiltinModule(`node:${moduleName}`));
const [crypto, fs, path, childProcess, https, http, zlib, dns, tls] = ['crypto', 'fs', 'path', 'child_process', 'https', 'http', 'zlib', 'dns', 'tls'].map((moduleName) => requireBuiltin(moduleName));
const { X509Certificate } = crypto;
const SELF = path.resolve(process.argv[1]), BASE_DIR = path.dirname(SELF);

// ========== 用户配置 ==========
// 优先级：真实环境变量 > 同目录 .env > 默认值。变量"未设置"才用默认值，设成空就是关闭
loadEnv(path.join(BASE_DIR, '.env'));
const CONFIG = {
  NAME: readEnv('NAME'),
  UUID: readEnv('UUID', '') || crypto.randomUUID(),
  CLOUDFLARE_TUNNEL_TOKEN: readEnv('CLOUDFLARE_TUNNEL_TOKEN'),
  CLOUDFLARE_IP: readEnv('CLOUDFLARE_IP', 'visa.cn'),
  PORT: readEnv('PORT').replace(/^0+$/, ''),
  VLESS_MODE: readMode('VLESS_MODE', 'trojan'),
  VMESS_MODE: readMode('VMESS_MODE'),
  TROJAN_MODE: readMode('TROJAN_MODE', 'vmess'),
  SHADOWSOCKS_MODE: readMode('SHADOWSOCKS_MODE'),
  HYSTERIA2_MODE: readEnv('HYSTERIA2_MODE'),
  MIXED_MODE: readEnv('MIXED_MODE'),
  WIREGUARD_MODE: readEnv('WIREGUARD_MODE'),
  CERT_HOST: readEnv('CERT_HOST').replace(/^[a-z]+:\/\//i, '').replace(/[/:].*$/, ''),
  WORK_DIR: path.resolve(BASE_DIR, readEnv('WORK_DIR', BASE_DIR)), // 下载的程序、日志、证书都放这里；留空 = 脚本所在目录
  KOMARI_ENDPOINT: readEnv('KOMARI_ENDPOINT'),
  KOMARI_TOKEN: readEnv('KOMARI_TOKEN'),
};
const {
  NAME, UUID, CLOUDFLARE_TUNNEL_TOKEN, CLOUDFLARE_IP, PORT, VLESS_MODE, VMESS_MODE, TROJAN_MODE, SHADOWSOCKS_MODE,
  HYSTERIA2_MODE, MIXED_MODE, WIREGUARD_MODE, CERT_HOST, KOMARI_ENDPOINT, KOMARI_TOKEN,
} = CONFIG;
console.log('[ENV]', Object.entries(CONFIG).filter(([, value]) => value).map(([key, value]) => `${key}=${/UUID|TOKEN/.test(key) ? `${value.slice(0, 4)}***` : value}`).join(' '));

// 先用 WORK_DIR，无法创建或读写时退回 /tmp/xray，仍不行就退出
let WORK_DIR = '';
for (const directory of new Set([CONFIG.WORK_DIR, '/tmp/xray'])) {
  try {
    fs.mkdirSync(directory, { recursive: true });
    fs.accessSync(directory, fs.constants.R_OK | fs.constants.W_OK);
    WORK_DIR = directory;
    break;
  } catch (error) { console.error(`[DIR] Cannot access ${directory}: ${error.message}`); }
}
if (!WORK_DIR) process.exit(1);
if (WORK_DIR !== CONFIG.WORK_DIR) console.log(`[DIR] Falling back to ${WORK_DIR}`);

function readLog(file) { try { return fs.readFileSync(file, 'utf8'); } catch { return ''; } }
function readEnv(key, defaultValue = '') { return (process.env[key] ?? defaultValue).trim(); }
function readMode(key, defaultValue = '') { return readEnv(key, defaultValue).toLowerCase(); }
function loadEnv(file) {
  try { return process.loadEnvFile(file); } catch (error) { if (error.code === 'ENOENT') return; }
  for (const line of readLog(file).split(/\r?\n/)) {
    const match = line.match(/^\s*(?:export\s+)?([A-Za-z_]\w*)\s*=\s*(.*)$/);
    if (!match || line.trim().startsWith('#')) continue;
    const rawValue = match[2].trim(), quoted = rawValue.match(/^(['"])(.*?)\1/);
    if (process.env[match[1]] === undefined) process.env[match[1]] = quoted ? quoted[2] : rawValue.replace(/\s+#.*$/, '');
  }
}

// 把当前 UUID 写回脚本本身：下次运行直接沿用
try {
  fs.writeFileSync(SELF, fs.readFileSync(SELF, 'utf8').replace(/^ {2}UUID: .*$/m, () => `  UUID: readEnv('UUID', '${UUID}') || crypto.randomUUID(),`));
} catch (error) { console.error(`[UUID] Cannot persist UUID to script: ${error.message}`); }

process.chdir(WORK_DIR);
const ARCHITECTURE = { x64: 'amd64', arm64: 'arm64' }[process.arch];
if (!ARCHITECTURE) { console.error(`[ARCH] Unsupported architecture: ${process.arch}`); process.exit(1); }

// ========== 通用函数 ==========
const toBase64 = (data) => Buffer.from(data).toString('base64');
const sleep = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds));
const validPort = (value) => /^[0-9]+$/.test(value) && +value >= 1 && +value <= 65535;
const die = (message) => { console.error(`[MODE] ${message}`); process.exit(1); };
const nonEmpty = (file) => { try { return fs.statSync(file).size > 0; } catch { return false; } };
const urlEncode = (text) => encodeURIComponent(text).replace(/[!'()*]/g, (char) => `%${char.charCodeAt(0).toString(16).toUpperCase()}`);

// HTTPS 请求：跟随重定向；file 非空时把响应体写进文件，否则返回 { status, body }
function request(url, { family, timeout = 10000, file = null, redirects = 5 } = {}) {
  return new Promise((resolve, reject) => {
    const clientRequest = https.get(url, { family }, (response) => {
      const { statusCode: status, headers } = response;
      if ([301, 302, 303, 307, 308].includes(status) && headers.location) {
        response.resume();
        if (redirects <= 0) return reject(new Error('too many redirects'));
        return request(new URL(headers.location, url).href, { family, timeout, file, redirects: redirects - 1 }).then(resolve, reject);
      }
      if (!file) {
        const chunks = [];
        return response.on('data', (chunk) => chunks.push(chunk)).on('end', () => resolve({ status, body: Buffer.concat(chunks).toString() })).on('error', reject);
      }
      if (status >= 400) { response.resume(); return reject(new Error(`HTTP ${status}`)); }
      response.pipe(fs.createWriteStream(file).on('finish', () => resolve({ status })).on('error', reject));
    });
    clientRequest.setTimeout(timeout, () => clientRequest.destroy(new Error('timeout')));
    clientRequest.on('error', reject);
  });
}

// 先写 .part 再改名，失败返回 false
async function download(destination, url) {
  let lastError;
  for (let attempt = 0; attempt < 3; attempt++) {
    try { await request(url, { file: `${destination}.part` }); fs.renameSync(`${destination}.part`, destination); return true; } catch (error) { lastError = error; fs.rmSync(`${destination}.part`, { force: true }); await sleep(1000); }
  }
  console.error(`[DL] Download failed: ${url} (${[lastError?.code, lastError?.message].filter(Boolean).join(' ') || 'unknown error'})`);
  return false;
}

// 流式解压 zip：只读中央目录，逐文件边读边解压边写
async function unzip(zipFile, directory) {
  const { pipeline } = requireBuiltin('stream').promises, root = path.resolve(directory);
  const fileDescriptor = fs.openSync(zipFile, 'r'), fileSize = fs.fstatSync(fileDescriptor).size;
  const readAt = (length, position) => { const buffer = Buffer.alloc(length); fs.readSync(fileDescriptor, buffer, 0, length, position); return buffer; };
  const tail = readAt(Math.min(fileSize, 65557), Math.max(0, fileSize - 65557));
  let endOffset = tail.length - 22;
  while (endOffset >= 0 && tail.readUInt32LE(endOffset) !== 0x06054b50) endOffset--;
  if (endOffset < 0) throw new Error('not a zip file');
  const centralDirectory = readAt(tail.readUInt32LE(endOffset + 12), tail.readUInt32LE(endOffset + 16));
  try {
    for (let entryIndex = 0, cursor = 0; entryIndex < tail.readUInt16LE(endOffset + 10); entryIndex++) {
      const method = centralDirectory.readUInt16LE(cursor + 10), compressedSize = centralDirectory.readUInt32LE(cursor + 20);
      const nameLength = centralDirectory.readUInt16LE(cursor + 28), localHeaderOffset = centralDirectory.readUInt32LE(cursor + 42);
      const entryName = centralDirectory.toString('utf8', cursor + 46, cursor + 46 + nameLength);
      cursor += 46 + nameLength + centralDirectory.readUInt16LE(cursor + 30) + centralDirectory.readUInt16LE(cursor + 32);
      const entryPath = path.resolve(root, entryName);
      if (entryName.endsWith('/') || !entryPath.startsWith(root + path.sep)) continue;
      fs.mkdirSync(path.dirname(entryPath), { recursive: true });
      if (!compressedSize) { fs.writeFileSync(entryPath, ''); continue; }
      const localHeader = readAt(30, localHeaderOffset), dataStart = localHeaderOffset + 30 + localHeader.readUInt16LE(26) + localHeader.readUInt16LE(28);
      const source = fs.createReadStream(zipFile, { start: dataStart, end: dataStart + compressedSize - 1 }), output = fs.createWriteStream(entryPath);
      await (method === 0 ? pipeline(source, output) : pipeline(source, zlib.createInflateRaw(), output));
    }
  } finally { fs.closeSync(fileDescriptor); }
}

// Go 程序的内存参数：GOGC 调低；有容器内存限制时设 GOMEMLIMIT 软上限
const GO_ENV = (() => {
  const memoryLimit = +(readLog('/sys/fs/cgroup/memory.max').trim() || readLog('/sys/fs/cgroup/memory/memory.limit_in_bytes').trim());
  return { GOGC: '50', ...(memoryLimit > 0 && memoryLimit < 2 ** 40 ? { GOMEMLIMIT: `${Math.floor(memoryLimit * 0.6 / 1048576)}MiB` } : {}) };
})();

// 子进程：脚本退出时一并结束
const children = [];
process.on('exit', () => children.forEach((child) => { try { child.kill(); } catch { /* 已退出 */ } }));
for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, () => process.exit(0));

async function killPrevious(processName, tag) {
  try { childProcess.execFileSync('pkill', ['-x', processName], { stdio: 'ignore' }); } catch { return; }
  console.log(`[${tag}] Stopped previous ${processName}`);
  await sleep(1000);
}

function spawnBackground(binary, args, logFile, extraEnv = {}) {
  const fileDescriptor = fs.openSync(logFile, 'w');
  const child = childProcess.spawn(binary, args, { env: { ...process.env, ...GO_ENV, ...extraEnv }, stdio: ['ignore', fileDescriptor, fileDescriptor] });
  fs.closeSync(fileDescriptor);
  children.push(child);
  return child;
}

// ========== 协议与模式 ==========
const PROTOCOLS = ['vless', 'vmess', 'trojan', 'shadowsocks'];
const WS_PATH = { vless: `/${UUID}-vless`, vmess: `/${UUID}-vmess`, trojan: `/${UUID}-trojan`, shadowsocks: `/${UUID}-ss` };
// 内部连接用 abstract unix socket(名字带脚本目录哈希)；Shadowsocks 入站不支持 unix socket，用本机端口 40004(Reality 回落链) / 40005(ws 入口)
const SHADOWSOCKS_INTERNAL_PORT = 40004, SHADOWSOCKS_WS_INTERNAL_PORT = 40005;
const abstractSocket = (name) => `@xray-${crypto.createHash('sha1').update(BASE_DIR).digest('hex').slice(0, 8)}-${name}`;
const endpointOf = (protocol, name, shadowsocksPort) => (protocol === 'shadowsocks' ? { listen: '127.0.0.1', port: shadowsocksPort, dest: shadowsocksPort } : { listen: abstractSocket(name), dest: abstractSocket(name) });
const internalEndpoint = (protocol) => endpointOf(protocol, protocol, SHADOWSOCKS_INTERNAL_PORT);
const wsInternalEndpoint = (protocol) => endpointOf(protocol, `${protocol}-ws`, SHADOWSOCKS_WS_INTERNAL_PORT);
const FRONT_SOCKET = abstractSocket('front'), WEB_SOCKET = abstractSocket('web');
const DEFAULT_FRONT_PORT = 8000, WIREGUARD_CLIENT_ADDRESS = '10.0.0.2/32';
const MODES = { vless: VLESS_MODE, vmess: VMESS_MODE, trojan: TROJAN_MODE, shadowsocks: SHADOWSOCKS_MODE };
const NUMERIC_PORT = {}, FALLBACK = {}, FALLBACK_PARENT = {}; // 协议 -> 数字端口 / 回落到的协议 / 回落到它的协议
const CHAIN = {}, HEAD_PORT = {}, REALITY_PORT = {}; // Reality 链头 -> 整条链 / 监听端口；链上每个协议 -> 对外端口
const ENABLED = [], WS_PROTOCOLS = [], CHAIN_HEADS = []; // 启用的协议 / 用 ws·cloudflare 的协议 / Reality 链头
let ACTIVE_MODE = '', QUICK_TUNNEL = false, FRONT_ON = false, SHARE_FRONT = false, FRONT_TLS = false, FRONT_PORT = 0, XRAY_ON = false;
const ENCODED_NAME = urlEncode(NAME);

// 前置入口的非 ws 请求回落到内置 HTTP 服务：/UUID 返回订阅，其它路径转给 CERT_HOST:80(PORT 和 CERT_HOST 都填了才有)，否则 404
let WEB_DESTINATION = '';
if (PORT && CERT_HOST) {
  WEB_DESTINATION = `${CERT_HOST}:80`;
  if (!/^[A-Za-z0-9.-]+:[0-9]{1,5}$/.test(WEB_DESTINATION)) die(`CERT_HOST='${CERT_HOST}' is invalid (expected a domain or an IPv4 address)`);
  console.log(`[WEB] Other paths on the front port are forwarded to ${WEB_DESTINATION}`);
}

// Hysteria2(UDP)、Mixed(SOCKS5 + HTTP，账号密码都是 UUID)、WireGuard(UDP)：只接受数字端口
const modePort = (name, value, description) => {
  if (!value) return 0;
  if (!validPort(value)) die(`${name}='${value}' is invalid (expected a port number 1-65535, or empty to disable)`);
  console.log(`[MODE] port ${+value}/${description}`);
  return +value;
};
const HYSTERIA2_PORT = modePort('HYSTERIA2_MODE', HYSTERIA2_MODE, 'udp: hysteria2');
const MIXED_PORT = modePort('MIXED_MODE', MIXED_MODE, 'tcp: mixed (socks5 + http)');
const WIREGUARD_PORT = modePort('WIREGUARD_MODE', WIREGUARD_MODE, 'udp: wireguard');

// 1. 解析各协议的 *_MODE
function parseModes() {
  for (const protocol of PROTOCOLS) {
    const variableName = `${protocol.toUpperCase()}_MODE`;
    let hasFront = false, hasReality = false;
    for (const token of (MODES[protocol] || '').split(',').map((item) => item.trim()).filter(Boolean)) {
      if (token === 'ws' || token === 'cloudflare') {
        if (hasFront) die(`${variableName}: only one of ws / cloudflare is allowed`);
        if (ACTIVE_MODE && ACTIVE_MODE !== token) die(`Protocols using ws / cloudflare share one port (PORT), so they must use the same mode (got: ${ACTIVE_MODE} ${token})`);
        hasFront = true; WS_PROTOCOLS.push(protocol); ACTIVE_MODE = token;
        continue;
      }
      if (hasReality) die(`${variableName}: only one Reality entry (a port or a fallback protocol) is allowed`);
      hasReality = true;
      if (/^[0-9]+$/.test(token)) {
        if (!validPort(token)) die(`${variableName}='${token}': port must be 1-65535`);
        NUMERIC_PORT[protocol] = +token;
      } else if (/^[a-z]+$/.test(token)) {
        if (!PROTOCOLS.includes(token)) die(`${variableName}='${token}' is not valid (expected ws / cloudflare / a port, or a fallback protocol: ${PROTOCOLS.join(' ')})`);
        if (token === protocol) die(`${variableName}='${token}': a protocol cannot fall back to itself`);
        if (protocol !== 'vless' && protocol !== 'trojan') die(`${variableName}='${token}': ${protocol.toUpperCase()} has no fallback ability, only VLESS and TROJAN can choose a fallback`);
        FALLBACK[protocol] = token;
      } else die(`${variableName}='${token}' is invalid (expected: ws / cloudflare / a port / a protocol name, comma separated, or empty to disable)`);
    }
  }
  QUICK_TUNNEL = ACTIVE_MODE === 'cloudflare' && CLOUDFLARE_TUNNEL_TOKEN === 'try'; // Token 填 try = 临时隧道
}

// 2. 把回落关系整理成 Reality 链
function buildChains() {
  // 回落目标没有 Reality 项时，指向它的协议也当作空，并逐级向上传递
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
    if (FALLBACK_PARENT[target]) die(`${target.toUpperCase()} is the fallback of both ${FALLBACK_PARENT[target].toUpperCase()} and ${protocol.toUpperCase()}, it can only have one`);
    FALLBACK_PARENT[target] = protocol;
  }
  for (const protocol of PROTOCOLS) {
    const hasReality = !!(NUMERIC_PORT[protocol] || FALLBACK[protocol]);
    if (WS_PROTOCOLS.includes(protocol) || hasReality || FALLBACK_PARENT[protocol]) ENABLED.push(protocol);
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
  for (const protocol of ENABLED) if ((NUMERIC_PORT[protocol] || FALLBACK[protocol] || FALLBACK_PARENT[protocol]) && !REALITY_PORT[protocol]) die(`${protocol.toUpperCase()} is part of a fallback loop: the chain needs a head that no protocol falls back to`);
}

// 3. 前置入口：是否需要、监听端口、是否与某条 Reality 链共用
function planFront() {
  if (!ACTIVE_MODE && !PORT) return;
  FRONT_ON = true;
  const frontPort = ACTIVE_MODE === 'cloudflare' ? DEFAULT_FRONT_PORT : (PORT || DEFAULT_FRONT_PORT);
  if (!validPort(String(frontPort))) die(`PORT='${PORT}' is not a valid port`);
  FRONT_PORT = +frontPort;
  if (PORT && ACTIVE_MODE !== 'cloudflare' && CHAIN_HEADS.some((head) => HEAD_PORT[head] === FRONT_PORT)) SHARE_FRONT = true; // Reality 认不出的流量转给前置入口
}

// 4. 端口检查
function checkPorts() {
  const ports = CHAIN_HEADS.map((head) => HEAD_PORT[head]);
  if (FRONT_ON && !SHARE_FRONT) ports.push(FRONT_PORT);
  if (MIXED_PORT) ports.push(MIXED_PORT);
  const duplicate = ports.find((port, index) => ports.indexOf(port) !== index);
  if (duplicate !== undefined) die(`Port ${duplicate} is used more than once: every Reality chain, the ws / cloudflare group (PORT) and MIXED_MODE need different TCP ports`);
  const conflicting = ports.find((port) => port === SHADOWSOCKS_INTERNAL_PORT || port === SHADOWSOCKS_WS_INTERNAL_PORT);
  if (conflicting !== undefined) die(`Port ${conflicting} conflicts with the internal ports 40004 / 40005 used by Shadowsocks`);
}

// ========== TLS 证书(供 ws / Hysteria2 使用) ==========
// CERT_HOST 是域名且 WORK_DIR 下有 $CERT_HOST.crt/.key 并且可信 -> 使用；否则自签证书
const IPV4_PATTERN = /^[0-9]{1,3}(\.[0-9]{1,3}){3}$/;
let CERT_FILE = '', KEY_FILE = '', TLS_SERVER_NAME = '', TLS_INSECURE = true, TLS_PINNED_CERT_SHA256 = '';

// 最小 DER 编码器：只够生成自签 X.509 证书
const Der = {
  length: (size) => (size < 128 ? Buffer.from([size]) : size < 256 ? Buffer.from([0x81, size]) : Buffer.from([0x82, size >> 8, size & 255])),
  tlv: (tag, ...children) => { const body = Buffer.concat(children); return Buffer.concat([Buffer.from([tag]), Der.length(body.length), body]); },
  sequence: (...children) => Der.tlv(0x30, ...children),
  integer: (buffer) => Der.tlv(0x02, buffer[0] & 0x80 ? Buffer.concat([Buffer.from([0]), buffer]) : buffer),
  oid: (dotted) => {
    const parts = dotted.split('.').map(Number), bytes = [parts[0] * 40 + parts[1]];
    for (const part of parts.slice(2)) { const encoded = [part & 127]; for (let rest = part >> 7; rest; rest >>= 7) encoded.unshift((rest & 127) | 128); bytes.push(...encoded); }
    return Der.tlv(0x06, Buffer.from(bytes));
  },
  utcTime: (date) => Der.tlv(0x17, Buffer.from(date.toISOString().replace(/^\d\d(\d\d)-(\d\d)-(\d\d)T(\d\d):(\d\d):(\d\d).*$/, '$1$2$3$4$5$6Z'))),
};

// 自签证书(RSA 2048，10 年)；已有且 30 天内不过期就复用(否则证书哈希变化会使订阅失效)
function generateSelfSignedCert(commonName) {
  const directory = path.join(WORK_DIR, '.selfsigned');
  fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
  CERT_FILE = path.join(directory, `${commonName}.crt`); KEY_FILE = path.join(directory, `${commonName}.key`);
  if (nonEmpty(CERT_FILE) && nonEmpty(KEY_FILE)) {
    try { if (Date.parse(new X509Certificate(fs.readFileSync(CERT_FILE)).validTo) - Date.now() > 30 * 86400e3) return; } catch { /* 重新生成 */ }
  }
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const subject = Der.sequence(Der.tlv(0x31, Der.sequence(Der.oid('2.5.4.3'), Der.tlv(0x0c, Buffer.from(commonName)))));
  const signatureAlgorithm = Der.sequence(Der.oid('1.2.840.113549.1.1.11'), Der.tlv(0x05));
  const serialNumber = crypto.randomBytes(16); serialNumber[0] = (serialNumber[0] & 0x7f) || 1;
  const subjectAltName = Der.tlv(0xa3, Der.sequence(Der.sequence(Der.oid('2.5.29.17'), Der.tlv(0x04, Der.sequence(Der.tlv(0x82, Buffer.from(commonName)), Der.tlv(0x82, Buffer.from('localhost')))))));
  const tbsCertificate = Der.sequence(
    Der.tlv(0xa0, Der.integer(Buffer.from([2]))), Der.integer(serialNumber), signatureAlgorithm, subject,
    Der.sequence(Der.utcTime(new Date(Date.now() - 86400e3)), Der.utcTime(new Date(Date.now() + 3650 * 86400e3))), subject,
    publicKey.export({ type: 'spki', format: 'der' }), subjectAltName,
  );
  const certificate = Der.sequence(tbsCertificate, signatureAlgorithm, Der.tlv(0x03, Buffer.concat([Buffer.from([0]), crypto.sign('sha256', tbsCertificate, privateKey)])));
  fs.writeFileSync(CERT_FILE, `-----BEGIN CERTIFICATE-----\n${toBase64(certificate).match(/.{1,64}/g).join('\n')}\n-----END CERTIFICATE-----\n`);
  fs.writeFileSync(KEY_FILE, privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });
}

// 校验证书链：叶子含域名，逐级验签，最终落在系统信任根上；返回空串表示可信，否则返回原因
function verifyChain(certificates, hostname) {
  const leaf = certificates[0];
  if (!leaf.checkHost(hostname)) return 'hostname mismatch';
  const roots = (tls.getCACertificates ? tls.getCACertificates('default') : tls.rootCertificates).map((pem) => new X509Certificate(pem));
  const isValid = (certificate) => Date.now() >= Date.parse(certificate.validFrom) && Date.now() <= Date.parse(certificate.validTo);
  const isSignedBy = (certificate, issuer) => certificate.checkIssued(issuer) && certificate.verify(issuer.publicKey);
  let current = leaf;
  for (let depth = 0; depth < 8; depth++) {
    if (!isValid(current)) return 'certificate expired or not yet valid';
    if (roots.some((root) => root.fingerprint256 === current.fingerprint256 || (isValid(root) && isSignedBy(current, root)))) return '';
    current = certificates.slice(1).find((issuer) => issuer !== current && issuer.ca && isSignedBy(current, issuer));
    if (!current) return 'issuer is not trusted';
  }
  return 'chain too long';
}

function trustedCertForHost(hostname) {
  const certFile = path.join(WORK_DIR, `${hostname}.crt`), keyFile = path.join(WORK_DIR, `${hostname}.key`);
  if (!nonEmpty(certFile) || !nonEmpty(keyFile)) return false;
  let certificates;
  try {
    certificates = (fs.readFileSync(certFile, 'utf8').match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g) || []).map((pem) => new X509Certificate(pem));
    if (!certificates.length) throw new Error('no certificate found');
    if (!certificates[0].checkPrivateKey(crypto.createPrivateKey(fs.readFileSync(keyFile)))) { console.error(`[TLS] ${certFile} and ${keyFile} do not match`); return false; }
  } catch (error) { console.error(`[TLS] Cannot read ${certFile} / ${keyFile}: ${error.message}`); return false; }
  const reason = verifyChain(certificates, hostname);
  if (reason) { console.error(`[TLS] ${certFile} is not a trusted certificate for ${hostname}: ${reason}`); return false; }
  CERT_FILE = certFile; KEY_FILE = keyFile;
  return true;
}

function setupTls() {
  TLS_SERVER_NAME = CERT_HOST || 'www.nazhumi.com';
  TLS_INSECURE = !(CERT_HOST && !IPV4_PATTERN.test(CERT_HOST) && trustedCertForHost(CERT_HOST));
  if (TLS_INSECURE) {
    console.error(`[TLS] No trusted certificate available (put one at ${WORK_DIR}/<CERT_HOST>.crt and .key), using self-signed certificate`);
    generateSelfSignedCert(TLS_SERVER_NAME);
    TLS_PINNED_CERT_SHA256 = new X509Certificate(fs.readFileSync(CERT_FILE)).fingerprint256.replace(/:/g, '').toLowerCase(); // 新版客户端用证书哈希固定(链接里的 pcs)
  }
  console.log(`[TLS] Server name: ${TLS_SERVER_NAME}, insecure: ${TLS_INSECURE ? 1 : 0}, cert: ${CERT_FILE}, key: ${KEY_FILE}`);
}

// ========== 密钥 ==========
// 私钥由 UUID 派生(SHA-256 + 用途标签，按 X25519 规则整理)：同一 UUID 永远得到同一组密钥；encoding 为 base64 / base64url
function deriveKey(label, encoding) {
  const privateKey = crypto.createHash('sha256').update(`${label}:${UUID}`).digest();
  privateKey[0] &= 248; privateKey[31] = (privateKey[31] & 127) | 64;
  const publicKey = crypto.createPublicKey(crypto.createPrivateKey({
    key: Buffer.concat([Buffer.from('302e020100300506032b656e04220420', 'hex'), privateKey]), format: 'der', type: 'pkcs8',
  })).export({ type: 'spki', format: 'der' }).subarray(-32);
  return [privateKey.toString(encoding), Buffer.from(publicKey).toString(encoding)];
}

// ========== 链接里的连接地址 ==========
// CERT_HOST 填 IP -> 直接用；否则探测公网 IPv4，域名解析包含它时改用域名
let PUBLIC_ADDRESS = '';
const TRACE_URL = 'https://one.one.one.one/cdn-cgi/trace';

async function resolvePublicAddress() {
  if (IPV4_PATTERN.test(CERT_HOST)) PUBLIC_ADDRESS = CERT_HOST;
  else {
    const traceResponse = await request(TRACE_URL, { family: 4, timeout: 5000 }).catch(() => null);
    PUBLIC_ADDRESS = ((traceResponse && traceResponse.body.match(/^ip=(.*)$/m)) || [, ''])[1].trim();
    if (CERT_HOST && PUBLIC_ADDRESS) {
      const resolvedIps = await dns.promises.lookup(CERT_HOST, { family: 4, all: true }).then((list) => list.map((entry) => entry.address)).catch(() => []);
      if (resolvedIps.includes(PUBLIC_ADDRESS)) { console.log(`[NET] ${CERT_HOST} points to this server, using it instead of the IP`); PUBLIC_ADDRESS = CERT_HOST; }
    }
  }
  if (!PUBLIC_ADDRESS) console.error('[NET] Cannot determine the public address, links will be invalid (set CERT_HOST)');
  console.log(`[NET] Address in links: ${PUBLIC_ADDRESS}`);
}

// ========== Xray 配置 ==========
let REALITY_PRIVATE_KEY = '', REALITY_PUBLIC_KEY = '', VLESS_FLOW = '', IPV6_AVAILABLE = false;
let WIREGUARD_SERVER_PRIVATE = '', WIREGUARD_SERVER_PUBLIC = '', WIREGUARD_CLIENT_PRIVATE = '', WIREGUARD_CLIENT_PUBLIC = '';
const SNIFFING = { enabled: true, destOverride: ['http', 'tls', 'quic'], routeOnly: true };

const streamTcp = () => ({ network: 'tcp', security: 'none' });
const streamWs = (wsPath) => ({ network: 'ws', security: 'none', wsSettings: { path: wsPath } });
const streamReality = (destination = 'www.iij.ad.jp:443', serverName = 'www.iij.ad.jp') => ({
  network: 'tcp', security: 'reality',
  realitySettings: { show: false, dest: destination, xver: 0, serverNames: [serverName], privateKey: REALITY_PRIVATE_KEY, shortIds: ['cdcf853c'] },
});
const streamTls = (network, alpn, extra = {}) => ({
  network, security: 'tls',
  tlsSettings: { serverName: TLS_SERVER_NAME, alpn: [alpn], certificates: [{ certificateFile: CERT_FILE, keyFile: KEY_FILE }] },
  ...extra,
});

function protocolSettings(protocol, fallbacks, flow) {
  const fallbackSetting = fallbacks ? { fallbacks } : {};
  switch (protocol) {
    case 'vless': return { clients: [{ id: UUID, email: UUID, ...(flow ? { flow } : {}) }], decryption: 'none', ...fallbackSetting };
    case 'vmess': return { clients: [{ id: UUID, email: UUID }] };
    case 'trojan': return { clients: [{ password: UUID, email: UUID }], ...fallbackSetting };
    case 'shadowsocks': return { method: 'aes-256-gcm', password: UUID, network: 'tcp' };
  }
}

const inbound = (tag, listen, port, protocol, settings, streamSettings) => ({ tag, listen, port, protocol, settings, streamSettings, sniffing: SNIFFING });

function buildConfig() {
  const inbounds = [];
  if (FRONT_ON) {
    // 前置入口：按路径把 ws 流量回落给各内部 ws 入口，其余回落给内置 HTTP 服务；与 Reality 共用端口时只听内部 socket
    const fallbacks = [];
    for (const protocol of WS_PROTOCOLS) {
      const endpoint = wsInternalEndpoint(protocol);
      fallbacks.push({ path: WS_PATH[protocol], dest: endpoint.dest, xver: 0 });
      inbounds.push(inbound(`${protocol}-ws-in`, endpoint.listen, endpoint.port, protocol, protocolSettings(protocol), streamWs(WS_PATH[protocol])));
    }
    fallbacks.push({ dest: WEB_SOCKET, xver: 0 });
    const [listen, port] = SHARE_FRONT ? [FRONT_SOCKET, undefined] : ['::', FRONT_PORT];
    inbounds.push(inbound('front-in', listen, port, 'vless', protocolSettings('vless', fallbacks), FRONT_TLS ? streamTls('tcp', 'http/1.1') : streamTcp()));
  }
  for (const head of CHAIN_HEADS) { // Reality 链：链头监听自己的端口套 Reality；其余监听内部地址
    for (const protocol of CHAIN[head]) {
      const fallbacks = FALLBACK[protocol] ? [{ dest: internalEndpoint(FALLBACK[protocol]).dest, xver: 0 }] : undefined;
      if (protocol !== head) { const endpoint = internalEndpoint(protocol); inbounds.push(inbound(`${protocol}-in`, endpoint.listen, endpoint.port, protocol, protocolSettings(protocol, fallbacks), streamTcp())); continue; }
      const stream = SHARE_FRONT && HEAD_PORT[head] === FRONT_PORT ? streamReality(FRONT_SOCKET, TLS_SERVER_NAME) : streamReality();
      inbounds.push(inbound(`${protocol}-in`, '::', HEAD_PORT[head], protocol, protocolSettings(protocol, fallbacks, protocol === 'vless' ? VLESS_FLOW : ''), stream));
    }
  }
  if (HYSTERIA2_PORT) inbounds.push(inbound('hysteria2-in', '::', HYSTERIA2_PORT, 'hysteria', { version: 2, clients: [{ auth: UUID, email: UUID }] }, streamTls('hysteria', 'h3', { hysteriaSettings: { version: 2 } })));
  if (MIXED_PORT) inbounds.push(inbound('mixed-in', '::', MIXED_PORT, 'socks', { auth: 'password', accounts: [{ user: UUID, pass: UUID }], udp: false }, streamTcp()));
  if (WIREGUARD_PORT) inbounds.push(inbound('wireguard-in', '::', WIREGUARD_PORT, 'wireguard', { secretKey: WIREGUARD_SERVER_PRIVATE, peers: [{ publicKey: WIREGUARD_CLIENT_PUBLIC, allowedIPs: [WIREGUARD_CLIENT_ADDRESS] }], mtu: 1420 }));
  return {
    log: { loglevel: 'warning' },
    dns: { servers: ['https+local://1.1.1.1/dns-query'], queryStrategy: 'UseIPv4' },
    inbounds,
    outbounds: [{ tag: 'direct', protocol: 'freedom' }, { tag: 'block', protocol: 'blackhole' }],
    routing: {
      domainStrategy: 'IPIfNonMatch',
      rules: [
        { type: 'field', ip: ['geoip:private'], outboundTag: 'direct' },
        ...(IPV6_AVAILABLE ? [] : [{ type: 'field', ip: ['::/0'], outboundTag: 'block' }]), // 无 IPv6 出口时拒绝 IPv6 目标，让客户端回退 IPv4
        { type: 'field', domain: ['geosite:cn', 'geosite:category-ads-all'], outboundTag: 'block' },
        { type: 'field', ip: ['geoip:cn'], outboundTag: 'block' },
      ],
    },
  };
}

// ========== 订阅链接 ==========
let SHADOWSOCKS_USERINFO = '', CLOUDFLARE_TUNNEL_HOSTNAME = '';

function realityLink(protocol, port, name) {
  const serverName = SHARE_FRONT && port === FRONT_PORT ? TLS_SERVER_NAME : 'www.iij.ad.jp';
  const prefix = { vless: `encryption=none${VLESS_FLOW ? `&flow=${VLESS_FLOW}` : ''}&`, vmess: 'encryption=auto&' }[protocol] || '';
  const realityQuery = `security=reality&sni=${serverName}&fp=chrome&pbk=${REALITY_PUBLIC_KEY}&type=tcp&sid=cdcf853c`;
  return `${protocol === 'shadowsocks' ? 'ss' : protocol}://${protocol === 'shadowsocks' ? SHADOWSOCKS_USERINFO : UUID}@${PUBLIC_ADDRESS}:${port}?${prefix}${realityQuery}#${urlEncode(name)}`;
}

// ws / cloudflare 链接的共同参数
function wsParams() {
  if (ACTIVE_MODE === 'cloudflare') return { address: CLOUDFLARE_IP || CLOUDFLARE_TUNNEL_HOSTNAME, port: 443, host: CLOUDFLARE_TUNNEL_HOSTNAME, insecureQuery: '', vmessInsecure: 0, vmessExtra: null, vmessPinnedCert: '' };
  const insecure = TLS_INSECURE ? 1 : 0;
  return {
    address: PUBLIC_ADDRESS, port: FRONT_PORT, host: TLS_SERVER_NAME, vmessInsecure: insecure, vmessPinnedCert: TLS_PINNED_CERT_SHA256,
    vmessExtra: { allowInsecure: insecure, verify_cert: !TLS_INSECURE }, insecureQuery: TLS_INSECURE ? `&allowInsecure=1&pcs=${TLS_PINNED_CERT_SHA256}` : '',
  };
}

function wsLink(protocol, wsInfo, name) {
  const encodedName = urlEncode(name), wsPath = WS_PATH[protocol], encodedPath = wsPath.replace(/\//g, '%2F');
  if (ACTIVE_MODE === 'cloudflare' && (!CLOUDFLARE_TUNNEL_HOSTNAME || !CLOUDFLARE_TUNNEL_TOKEN)) {
    console.error(`[MODE] cloudflare mode needs CLOUDFLARE_TUNNEL_TOKEN (set it to 'try' for a quick tunnel) and a tunnel hostname found in the cloudflared log, no ${protocol} link generated`);
    return '';
  }
  const query = `sni=${wsInfo.host}&fp=chrome&type=ws&host=${wsInfo.host}&path=${encodedPath}${wsInfo.insecureQuery}#${encodedName}`;
  switch (protocol) {
    case 'vless': return `vless://${UUID}@${wsInfo.address}:${wsInfo.port}?encryption=none&security=tls&${query}`;
    case 'trojan': return `trojan://${UUID}@${wsInfo.address}:${wsInfo.port}?security=tls&${query}`;
    case 'vmess': return `vmess://${toBase64(JSON.stringify({
      v: '2', ps: name, add: wsInfo.address, port: String(wsInfo.port), id: UUID, aid: '0', scy: 'none', net: 'ws', type: 'none',
      host: wsInfo.host, path: wsPath + (ACTIVE_MODE === 'cloudflare' ? '?ed=2560' : ''), tls: 'tls', sni: wsInfo.host, alpn: '', fp: '', insecure: String(wsInfo.vmessInsecure), ...(wsInfo.vmessExtra || {}), vcn: '', pcs: wsInfo.vmessPinnedCert,
    }))}`; // ?ed=2560 为 0-RTT early data
    case 'shadowsocks': { // v2ray-plugin 无法跳过证书校验，自签证书下不输出
      if (ACTIVE_MODE === 'ws' && TLS_INSECURE) {
        console.error(`[MODE] ws mode: Shadowsocks (v2ray-plugin) needs a trusted certificate, put one at ${WORK_DIR}/<CERT_HOST>.crt and .key. No SS link generated`);
        return '';
      }
      const plugin = `v2ray-plugin;tls;host=${wsInfo.host};path=${wsPath};mux=0`.replace(/;/g, '%3B').replace(/=/g, '%3D').replace(/\//g, '%2F');
      return `ss://${SHADOWSOCKS_USERINFO}@${wsInfo.address}:${wsInfo.port}/?plugin=${plugin}#${encodedName}`;
    }
  }
}

// 一个协议可能输出两条链接(Reality + ws / cloudflare)，两条都有时节点名加后缀
function generateNodes(protocol, wsInfo) {
  const hasBoth = !!REALITY_PORT[protocol] && WS_PROTOCOLS.includes(protocol);
  return [
    REALITY_PORT[protocol] && realityLink(protocol, REALITY_PORT[protocol], hasBoth ? `${NAME}-reality` : NAME),
    WS_PROTOCOLS.includes(protocol) && wsLink(protocol, wsInfo, hasBoth ? `${NAME}-${ACTIVE_MODE}` : NAME),
  ].filter(Boolean);
}

const hysteria2Link = () => `hysteria2://${UUID}@${PUBLIC_ADDRESS}:${HYSTERIA2_PORT}/?sni=${TLS_SERVER_NAME}${TLS_INSECURE ? '&insecure=1' : ''}#${ENCODED_NAME}`;
const mixedLinks = () => ['socks5', 'http'].map((scheme) => `${scheme}://${UUID}:${UUID}@${PUBLIC_ADDRESS}:${MIXED_PORT}#${ENCODED_NAME}`).join('\n');
const wireguardLink = () => `wireguard://${urlEncode(WIREGUARD_CLIENT_PRIVATE)}@${PUBLIC_ADDRESS}:${WIREGUARD_PORT}?publickey=${urlEncode(WIREGUARD_SERVER_PUBLIC)}&address=${urlEncode(WIREGUARD_CLIENT_ADDRESS)}&mtu=1420#${ENCODED_NAME}`;
const wireguardConfig = () => `[Interface]\nPrivateKey = ${WIREGUARD_CLIENT_PRIVATE}\nAddress = ${WIREGUARD_CLIENT_ADDRESS}\nDNS = 1.1.1.1\nMTU = 1420\n\n[Peer]\nPublicKey = ${WIREGUARD_SERVER_PUBLIC}\nEndpoint = ${PUBLIC_ADDRESS}:${WIREGUARD_PORT}\nAllowedIPs = 0.0.0.0/0, ::/0\nPersistentKeepalive = 25\n`;

// ========== 内置 HTTP 服务(订阅 + 回落) ==========
// 监听 abstract unix socket：GET /UUID 返回 base64 订阅；其它路径转给 WEB_DESTINATION(没有就 404)
function startWeb(subscriptionBody) {
  const [destinationHost, destinationPort] = WEB_DESTINATION ? [WEB_DESTINATION.split(':')[0], +WEB_DESTINATION.split(':')[1]] : [];
  http.createServer((incomingRequest, serverResponse) => {
    const pathname = incomingRequest.url.split('?')[0];
    console.log(`[WEB] ${incomingRequest.method} ${pathname === `/${UUID}` ? '/UUID' : pathname}`);
    if ((incomingRequest.method === 'GET' || incomingRequest.method === 'HEAD') && pathname === `/${UUID}`) {
      serverResponse.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store' });
      return serverResponse.end(incomingRequest.method === 'HEAD' ? undefined : subscriptionBody);
    }
    if (!WEB_DESTINATION) { serverResponse.writeHead(404, { 'Content-Type': 'text/plain' }); return serverResponse.end('Not Found'); }
    const upstreamRequest = http.request({ host: destinationHost, port: destinationPort, path: incomingRequest.url, method: incomingRequest.method, headers: incomingRequest.headers }, (upstreamResponse) => { serverResponse.writeHead(upstreamResponse.statusCode, upstreamResponse.headers); upstreamResponse.pipe(serverResponse); });
    upstreamRequest.on('error', () => { serverResponse.writeHead(502); serverResponse.end(); });
    incomingRequest.pipe(upstreamRequest);
  }).on('error', (error) => console.error(`[WEB] HTTP service failed: ${error.message}`)).listen(`\0${WEB_SOCKET.slice(1)}`); // Node 里 abstract socket 以 \0 开头，Xray 里以 @ 开头
}

// ========== 外部程序 ==========
async function fetchBinary(fileName, url) {
  const binary = path.join(WORK_DIR, fileName);
  if (!await download(binary, url)) process.exit(1);
  fs.chmodSync(binary, 0o755);
  return binary;
}

// Komari 探针：有代理协议时后台运行；没有时前台运行
async function startKomari() {
  await killPrevious('komari-agent', 'KOMARI');
  const binary = await fetchBinary('komari-agent', `https://github.com/komari-monitor/komari-agent/releases/latest/download/komari-agent-linux-${ARCHITECTURE}`);
  const agentEnv = { AGENT_ENDPOINT: KOMARI_ENDPOINT, AGENT_TOKEN: KOMARI_TOKEN }; // 只传给这个进程
  if (XRAY_ON) {
    spawnBackground(binary, [], path.join(WORK_DIR, 'komari-agent.log'), agentEnv);
    return console.log(`[KOMARI] Agent started, reporting to ${KOMARI_ENDPOINT}`);
  }
  console.log(`[KOMARI] No proxy protocol enabled, running the agent only, reporting to ${KOMARI_ENDPOINT}`);
  const child = childProcess.spawn(binary, [], { env: { ...process.env, ...GO_ENV, ...agentEnv }, stdio: 'inherit' });
  children.push(child);
  child.on('exit', (exitCode) => process.exit(exitCode ?? 1));
  await new Promise(() => {});
}

// 取 cloudflared 日志里下发的第一条「有具体域名、Service 是 http://localhost:端口」的 ingress 规则
function parseIngress(text) {
  const match = text.split('\n').filter((line) => line.includes('Updated to new configuration')).pop()?.match(/config="(.*)" version=/);
  if (!match) return null;
  let config;
  try { config = JSON.parse(match[1].replace(/\\"/g, '"')); } catch { return null; }
  for (const rule of config.ingress || []) {
    const serviceMatch = rule.hostname && !rule.hostname.includes('*') && /^http:\/\/(?:localhost|127\.0\.0\.1):(\d+)$/.exec(rule.service || '');
    if (serviceMatch) return { hostname: rule.hostname, port: serviceMatch[1] };
  }
  return null;
}

// cloudflare 模式：Token 跑固定隧道；填 try 用临时隧道。域名和回源端口都从日志取
async function startCloudflared() {
  await killPrevious('cloudflared', 'CF');
  const binary = await fetchBinary('cloudflared', `https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-${ARCHITECTURE}`);
  const logFile = path.join(WORK_DIR, 'cloudflared.log');
  childProcess.spawnSync(binary, ['--version'], { stdio: 'inherit' });

  if (QUICK_TUNNEL) {
    spawnBackground(binary, ['--no-autoupdate', 'tunnel', '--url', `http://localhost:${FRONT_PORT}`], logFile);
    for (let attempt = 0; attempt < 30 && !CLOUDFLARE_TUNNEL_HOSTNAME; attempt++) {
      CLOUDFLARE_TUNNEL_HOSTNAME = [...readLog(logFile).matchAll(/https:\/\/([a-z0-9-]+\.trycloudflare\.com)/g)].map((match) => match[1]).find((hostname) => !hostname.startsWith('api.')) || '';
      if (!CLOUDFLARE_TUNNEL_HOSTNAME) await sleep(1000);
    }
    if (CLOUDFLARE_TUNNEL_HOSTNAME) console.log(`[CF] Quick tunnel hostname from log: ${CLOUDFLARE_TUNNEL_HOSTNAME} (service port=${FRONT_PORT})`);
    else console.error(`[CF] Cannot find the trycloudflare.com hostname in ${logFile}`);
    return;
  }

  spawnBackground(binary, ['--no-autoupdate', 'tunnel', 'run'], logFile, { TUNNEL_TOKEN: CLOUDFLARE_TUNNEL_TOKEN });
  for (let attempt = 0; attempt < 30 && !readLog(logFile).includes('Updated to new configuration'); attempt++) await sleep(1000);
  const rule = parseIngress(readLog(logFile));
  if (rule && validPort(rule.port)) {
    CLOUDFLARE_TUNNEL_HOSTNAME = rule.hostname;
    FRONT_PORT = +rule.port;
    checkPorts(); // 端口变了，重新检查冲突
    console.log(`[CF] From cloudflared log: hostname=${CLOUDFLARE_TUNNEL_HOSTNAME}, tunnel service port=${FRONT_PORT}`);
  } else console.error(`[CF] Cannot read hostname / port from ${logFile} (the tunnel needs a Public hostname without * and a Service like http://localhost:PORT)`);
}

// ========== 主流程 ==========
async function main() {
  parseModes();
  buildChains();
  planFront();
  FRONT_TLS = ACTIVE_MODE === 'ws' || SHARE_FRONT; // ws 模式或与 Reality 共用端口时前置入口带 TLS
  checkPorts();

  if (ENABLED.length) console.log(`[MODE] enabled=${ENABLED.join(' ')}`);
  if (ACTIVE_MODE) console.log(`[MODE] port ${FRONT_PORT}: ${ACTIVE_MODE} (${WS_PROTOCOLS.join(' ')})${SHARE_FRONT ? ' shared with reality' : ''}`);
  for (const head of CHAIN_HEADS) console.log(`[MODE] port ${HEAD_PORT[head]}: reality (${CHAIN[head].join(' -> ')})`);
  VLESS_FLOW = CHAIN_HEADS.includes('vless') ? 'xtls-rprx-vision' : ''; // Vision 仅 VLESS 作 Reality 链头时支持

  const KOMARI_ENABLED = !!(KOMARI_ENDPOINT && KOMARI_TOKEN);
  if (!XRAY_ON && !KOMARI_ENABLED) die('Nothing to run: set a protocol *_MODE / HYSTERIA2_MODE / MIXED_MODE / WIREGUARD_MODE, or KOMARI_ENDPOINT + KOMARI_TOKEN');
  if (KOMARI_ENABLED) await startKomari();

  if (CHAIN_HEADS.length) {
    [REALITY_PRIVATE_KEY, REALITY_PUBLIC_KEY] = deriveKey('reality', 'base64url');
    console.log(`[REALITY] Private key: ${REALITY_PRIVATE_KEY}\n[REALITY] Public key: ${REALITY_PUBLIC_KEY}`);
  }
  if (WIREGUARD_PORT) {
    [WIREGUARD_SERVER_PRIVATE, WIREGUARD_SERVER_PUBLIC] = deriveKey('wg-server', 'base64');
    [WIREGUARD_CLIENT_PRIVATE, WIREGUARD_CLIENT_PUBLIC] = deriveKey('wg-client', 'base64');
  }
  SHADOWSOCKS_USERINFO = Buffer.from(`aes-256-gcm:${UUID}`).toString('base64url');

  if (ACTIVE_MODE !== 'cloudflare' || CHAIN_HEADS.length || HYSTERIA2_PORT || MIXED_PORT || WIREGUARD_PORT) await resolvePublicAddress();
  IPV6_AVAILABLE = await request(TRACE_URL, { family: 6, timeout: 5000 }).then(() => true, () => false);
  console.log(IPV6_AVAILABLE ? '[NET] IPv6 egress: available' : '[NET] IPv6 egress: unavailable, blocking IPv6 destinations');
  if (FRONT_TLS || HYSTERIA2_PORT) setupTls();
  if (ACTIVE_MODE === 'cloudflare' && CLOUDFLARE_TUNNEL_TOKEN) await startCloudflared();

  // ---- Xray ----
  const xrayDirectory = WORK_DIR, xrayBinary = path.join(xrayDirectory, 'xray'), xrayConfigFile = path.join(xrayDirectory, 'config.json'), zipFile = path.join(WORK_DIR, 'xray.zip');
  if (!await download(zipFile, `https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-${ARCHITECTURE === 'amd64' ? '64' : 'arm64-v8a'}.zip`)) process.exit(1);
  await unzip(zipFile, xrayDirectory);
  fs.rmSync(zipFile, { force: true });
  try { fs.chmodSync(xrayBinary, 0o755); } catch { /* 下面统一检查 */ }
  if (!nonEmpty(xrayBinary)) { console.error(`[XRAY] Binary not found after extraction: ${xrayBinary}`); process.exit(1); }
  const xrayEnv = { ...process.env, ...GO_ENV, XRAY_LOCATION_ASSET: xrayDirectory };
  const runXray = (args) => childProcess.spawnSync(xrayBinary, args, { stdio: 'inherit', env: xrayEnv });
  runXray(['version']);

  fs.writeFileSync(xrayConfigFile, '', { mode: 0o600 }); // 先收紧权限再写入(含 UUID 和 Reality 私钥)
  fs.chmodSync(xrayConfigFile, 0o600);
  fs.writeFileSync(xrayConfigFile, `${JSON.stringify(buildConfig(), null, 2)}\n`);
  if (runXray(['run', '-test', '-c', xrayConfigFile]).status !== 0) { console.error('[XRAY] Config test failed, aborting'); process.exit(1); }

  // ---- 输出订阅 ----
  const wsInfo = ACTIVE_MODE ? wsParams() : null;
  const nodes = ENABLED.flatMap((protocol) => generateNodes(protocol, wsInfo));
  if (HYSTERIA2_PORT) nodes.push(hysteria2Link());
  if (MIXED_PORT) nodes.push(mixedLinks());
  if (WIREGUARD_PORT) nodes.push(wireguardLink());
  const allNodes = nodes.filter(Boolean).map((node) => `${node}\n`).join('');
  console.log(`\n=== Nodes ===\n${allNodes}\n=== Subscription (base64) ===\n${toBase64(allNodes)}\n`);
  if (WIREGUARD_PORT) console.log(`\n=== WireGuard config (wg-quick) ===\n${wireguardConfig()}`);
  if (FRONT_ON) {
    startWeb(toBase64(allNodes));
    const baseUrl = ACTIVE_MODE === 'cloudflare' ? (CLOUDFLARE_TUNNEL_HOSTNAME && `https://${CLOUDFLARE_TUNNEL_HOSTNAME}`) : `${FRONT_TLS ? 'https' : 'http'}://${PUBLIC_ADDRESS}:${FRONT_PORT}`;
    if (baseUrl) console.log(`\n=== Subscription URL ===\n${baseUrl}/${UUID}${FRONT_TLS && TLS_INSECURE ? '\n(自签证书：客户端需要允许不校验证书)' : ''}\n`);
  }

  try { requireBuiltin('v8').setFlagsFromString('--expose-gc'); requireBuiltin('vm').runInNewContext('gc')(); } catch { /* 没有就算了 */ }
  const xrayProcess = childProcess.spawn(xrayBinary, ['run', '-c', xrayConfigFile], { stdio: 'inherit', env: xrayEnv });
  children.push(xrayProcess);
  xrayProcess.on('exit', (exitCode) => process.exit(exitCode ?? 1));
}

main().catch((error) => { console.error(error); process.exit(1); });
