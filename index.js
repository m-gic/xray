#!/usr/bin/env node
'use strict';
// 纯 Node.js 实现，只用内置模块，不需要 npm install / openssl / unzip / curl；需要 Node.js 16 及以上
// 多模式：每个 *_MODE 可用逗号分隔，例如 VLESS_MODE=ws,443 (一个前置模式 ws/cloudflare + 一个 Reality 项：端口或回落协议名)
const bi = (m) => (typeof require === 'function' ? require(m) : process.getBuiltinModule(`node:${m}`)); // CJS 用 require；ESM 用 getBuiltinModule(Node 22.3+)
const crypto = bi('crypto'), fs = bi('fs'), path = bi('path'), cp = bi('child_process');
const https = bi('https'), http = bi('http'), zlib = bi('zlib'), dns = bi('dns'), tls = bi('tls');
const { X509Certificate } = crypto;
const SELF = path.resolve(process.argv[1]), BASE_DIR = path.dirname(SELF);

// ========== 用户配置 ==========
const CONFIG = {
  NAME: process.env.NAME || '',
  UUID: process.env.UUID || '' || crypto.randomUUID(),
  CLOUDFLARE_TUNNEL_TOKEN: process.env.CLOUDFLARE_TUNNEL_TOKEN || '',
  CLOUDFLARE_IP: process.env.CLOUDFLARE_IP || '',
  PORT: /^0*$/.test(process.env.PORT || '') ? '' : process.env.PORT,
  VLESS_MODE: process.env.VLESS_MODE || '',
  VMESS_MODE: process.env.VMESS_MODE || '',
  TROJAN_MODE: process.env.TROJAN_MODE || '',
  SHADOWSOCKS_MODE: process.env.SHADOWSOCKS_MODE || '',
  HYSTERIA2_MODE: process.env.HYSTERIA2_MODE || '',
  MIXED_MODE: process.env.MIXED_MODE || '',
  WIREGUARD_MODE: process.env.WIREGUARD_MODE || '',
  CERT_HOST: process.env.CERT_HOST || '',
  KOMARI_ENDPOINT: process.env.KOMARI_ENDPOINT || '',
  KOMARI_TOKEN: process.env.KOMARI_TOKEN || '',
};
const {
  NAME, UUID, CLOUDFLARE_TUNNEL_TOKEN, CLOUDFLARE_IP, PORT, VLESS_MODE, VMESS_MODE, TROJAN_MODE, SHADOWSOCKS_MODE,
  HYSTERIA2_MODE, MIXED_MODE, WIREGUARD_MODE, CERT_HOST, KOMARI_ENDPOINT, KOMARI_TOKEN,
} = CONFIG;

// 把当前 UUID 写回脚本本身(填进上面 UUID 那行的 '' 里)：下次运行直接沿用，不做任何检测
fs.writeFileSync(SELF, fs.readFileSync(SELF, 'utf8').replace(/^ {2}UUID: .*$/m, () => `  UUID: process.env.UUID || '${UUID}' || crypto.randomUUID(),`));

process.chdir(BASE_DIR);
const ARCH = { x64: 'amd64', arm64: 'arm64' }[process.arch];
if (!ARCH) { console.error(`[ARCH] Unsupported architecture: ${process.arch}`); process.exit(1); }

// ========== 通用函数 ==========
const b64 = (b) => Buffer.from(b).toString('base64');
const b64url = (b) => Buffer.from(b).toString('base64url');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const validPort = (v) => /^[0-9]+$/.test(v) && +v >= 1 && +v <= 65535;
const die = (msg) => { console.error(`[MODE] ${msg}`); process.exit(1); };
const nonEmpty = (f) => { try { return fs.statSync(f).size > 0; } catch { return false; } };
const readLog = (f) => { try { return fs.readFileSync(f, 'utf8'); } catch { return ''; } };
const urlencode = (s) => [...Buffer.from(String(s))]
  .map((b) => { const c = String.fromCharCode(b); return /[A-Za-z0-9.~_-]/.test(c) ? c : `%${b.toString(16).toUpperCase().padStart(2, '0')}`; }).join('');

// HTTPS 请求：跟随重定向；file 不为空时把响应体写进文件(HTTP 错误视为失败)，否则返回 { status, body }
function request(url, { family, timeout = 10000, file = null, redirects = 5 } = {}) {
  return new Promise((resolve, reject) => {
    const req = https.get(url, { family }, (res) => {
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
    req.setTimeout(timeout, () => req.destroy(new Error('timeout')));
    req.on('error', reject);
  });
}

// 先写 .part 再改名，失败(含 HTTP 错误)返回 false，不留半截文件
async function dl(dest, url) {
  for (let i = 0; i < 3; i++) {
    try { await request(url, { file: `${dest}.part` }); fs.renameSync(`${dest}.part`, dest); return true; } catch { fs.rmSync(`${dest}.part`, { force: true }); await sleep(1000); }
  }
  console.error(`[DL] Download failed: ${url}`);
  return false;
}

// 流式解压 zip(Xray 发行包)：只读中央目录，每个文件边读、边解压、边写，内存占用恒定(不把整个压缩包和解压后的文件读进内存)
async function unzip(zipFile, dir) {
  const { pipeline } = bi('stream').promises, root = path.resolve(dir);
  const fd = fs.openSync(zipFile, 'r'), size = fs.fstatSync(fd).size;
  const readAt = (len, pos) => { const buf = Buffer.alloc(len); fs.readSync(fd, buf, 0, len, pos); return buf; };
  const tail = readAt(Math.min(size, 65557), Math.max(0, size - 65557));
  let e = tail.length - 22;
  while (e >= 0 && tail.readUInt32LE(e) !== 0x06054b50) e--;
  if (e < 0) throw new Error('not a zip file');
  const cd = readAt(tail.readUInt32LE(e + 12), tail.readUInt32LE(e + 16));
  try {
    for (let i = 0, p = 0; i < tail.readUInt16LE(e + 10); i++) {
      const method = cd.readUInt16LE(p + 10), csize = cd.readUInt32LE(p + 20), nlen = cd.readUInt16LE(p + 28), off = cd.readUInt32LE(p + 42);
      const name = cd.toString('utf8', p + 46, p + 46 + nlen);
      p += 46 + nlen + cd.readUInt16LE(p + 30) + cd.readUInt16LE(p + 32);
      const f = path.resolve(root, name);
      if (name.endsWith('/') || !f.startsWith(root + path.sep)) continue;
      fs.mkdirSync(path.dirname(f), { recursive: true });
      if (!csize) { fs.writeFileSync(f, ''); continue; }
      const lh = readAt(30, off), start = off + 30 + lh.readUInt16LE(26) + lh.readUInt16LE(28);
      const src = fs.createReadStream(zipFile, { start, end: start + csize - 1 }), out = fs.createWriteStream(f);
      await (method === 0 ? pipeline(src, out) : pipeline(src, zlib.createInflateRaw(), out));
    }
  } finally { fs.closeSync(fd); }
}

// Go 程序(Xray / cloudflared / 探针)的内存参数：GOGC 调低让垃圾回收更勤；容器有内存限制时再设 GOMEMLIMIT 软上限(接近时 GC 更积极，避免被 OOM 杀掉)
const GO_ENV = (() => {
  const rd = (f) => { try { return fs.readFileSync(f, 'utf8').trim(); } catch { return ''; } };
  const limit = +(rd('/sys/fs/cgroup/memory.max') || rd('/sys/fs/cgroup/memory/memory.limit_in_bytes')); // 没有限制时是 'max' 或一个巨大的数
  return { GOGC: '50', ...(limit > 0 && limit < 2 ** 40 ? { GOMEMLIMIT: `${Math.floor(limit * 0.6 / 1048576)}MiB` } : {}) };
})();

// 子进程：脚本退出(含 SIGINT / SIGTERM)时一并结束
const children = [];
process.on('exit', () => children.forEach((c) => { try { c.kill(); } catch { /* 已退出 */ } }));
for (const sig of ['SIGINT', 'SIGTERM']) process.on(sig, () => process.exit(0));

// 按进程名停掉上一次留下的同名进程；没有 pkill 或没有旧进程时什么都不做
async function killPrevious(name, tag) {
  try { cp.execFileSync('pkill', ['-x', name], { stdio: 'ignore' }); } catch { return; }
  console.log(`[${tag}] Stopped previous ${name}`);
  await sleep(1000);
}

// 后台运行，输出写到日志文件
function spawnBg(bin, args, logFile, extraEnv = {}) {
  const fd = fs.openSync(logFile, 'w');
  const child = cp.spawn(bin, args, { env: { ...process.env, ...GO_ENV, ...extraEnv }, stdio: ['ignore', fd, fd] });
  fs.closeSync(fd);
  children.push(child);
  return child;
}

// ========== 协议与模式 ==========
const PROTOS = ['vless', 'vmess', 'trojan', 'shadowsocks'];
// 各协议的 ws 路径
const WS_PATH = { vless: `/${UUID}-vless`, vmess: `/${UUID}-vmess`, trojan: `/${UUID}-trojan`, shadowsocks: `/${UUID}-ss` };
// 内部连接(前置入口回落、Reality 回落链、订阅服务)不占 TCP 端口：用 abstract unix socket，名字带上脚本目录的哈希，同一台机器上跑多份也不会冲突。
// 只有 Shadowsocks 入站不支持 unix socket，只能用本机 TCP 端口：40004 给 Reality 回落链，40005 给 ws 入口(同一协议可以同时开两种模式)
const SS_IPORT = 40004, SS_WS_IPORT = 40005;
const SOCK = (n) => `@xray-${crypto.createHash('sha1').update(BASE_DIR).digest('hex').slice(0, 8)}-${n}`;
const internal = (p) => (p === 'shadowsocks' ? { listen: '127.0.0.1', port: SS_IPORT, dest: SS_IPORT } : { listen: SOCK(p), dest: SOCK(p) });
const wsInternal = (p) => (p === 'shadowsocks' ? { listen: '127.0.0.1', port: SS_WS_IPORT, dest: SS_WS_IPORT } : { listen: SOCK(`${p}-ws`), dest: SOCK(`${p}-ws`) });
const FRONT_SOCK = SOCK('front'), WEB_SOCK = SOCK('web');
const DEFAULT_FRONT_PORT = 8000, WG_CLIENT_ADDR = '10.0.0.2/32';
const MODES = { vless: VLESS_MODE, vmess: VMESS_MODE, trojan: TROJAN_MODE, shadowsocks: SHADOWSOCKS_MODE };
const NPORT = {}, FB = {}, PARENT = {}; // 协议 -> 数字端口 / 回落到的协议 / 回落到它的协议
const CHAIN = {}, HPORT = {}, RPORT = {}; // Reality 链头 -> 整条链 / 监听端口；链上每个协议 -> 对外端口
const ENABLED = [], SHARED = [], HEADS = []; // 启用的协议 / 用 ws·cloudflare·try 的协议 / Reality 链头
let ACTIVE_MODE = '', TRY_TUNNEL = false, FRONT_ON = false, SHARE_FRONT = false, FRONT_TLS = false, FRONT_PORT = 0, XRAY_ON = false;
const NAME_ENC = urlencode(NAME);

// 前置入口收到的非 ws 请求都回落到本机内置的 HTTP 服务(见 startWeb)：/UUID 返回订阅，其它路径转给 CERT_HOST 的 80 端口(PORT 和 CERT_HOST 都填了才有)，没有就返回 404
let WEB_DEST = '';
if (PORT && CERT_HOST) {
  WEB_DEST = `${CERT_HOST}:80`;
  if (!/^[A-Za-z0-9.-]+:[0-9]{1,5}$/.test(WEB_DEST)) die(`CERT_HOST='${CERT_HOST}' is invalid (expected a domain or an IPv4 address)`);
  console.log(`[WEB] Other paths on the front port are forwarded to ${WEB_DEST}`);
}

// Hysteria2(UDP)、Mixed(SOCKS5 + HTTP，TCP，账号和密码都是 UUID)、WireGuard(UDP)：只接受数字端口，不参与回落链
const modePort = (name, v, desc) => {
  if (!v) return 0;
  if (!validPort(v)) die(`${name}='${v}' is invalid (expected a port number 1-65535, or empty to disable)`);
  console.log(`[MODE] port ${+v}/${desc}`);
  return +v;
};
const HY2_PORT = modePort('HYSTERIA2_MODE', HYSTERIA2_MODE, 'udp: hysteria2');
const MIXED_PORT = modePort('MIXED_MODE', MIXED_MODE, 'tcp: mixed (socks5 + http)');
const WG_PORT = modePort('WIREGUARD_MODE', WIREGUARD_MODE, 'udp: wireguard');

// 1. 解析各协议的 *_MODE(可用逗号分隔多个)：
//    前置模式 ws / cloudflare(最多一个)；Reality 项(最多一个)：数字端口，或协议名(回落)
function parseModes() {
  for (const p of PROTOS) {
    const v = `${p.toUpperCase()}_MODE`;
    const toks = (MODES[p] || '').split(',').map((s) => s.trim()).filter(Boolean);
    let front = false, reality = false;
    for (const m of toks) {
      if (m === 'ws' || m === 'cloudflare') {
        if (front) die(`${v}: only one of ws / cloudflare is allowed`);
        if (ACTIVE_MODE && ACTIVE_MODE !== m) die(`Protocols using ws / cloudflare share one port (PORT), so they must use the same mode (got: ${ACTIVE_MODE} ${m})`);
        front = true; SHARED.push(p); ACTIVE_MODE = m;
        continue;
      }
      if (reality) die(`${v}: only one Reality entry (a port or a fallback protocol) is allowed`);
      reality = true;
      if (/^[0-9]+$/.test(m)) {
        if (!validPort(m)) die(`${v}='${m}': port must be 1-65535`);
        NPORT[p] = +m;
      } else if (/^[a-z]+$/.test(m)) {
        if (!PROTOS.includes(m)) die(`${v}='${m}': '${m}' is not valid (expected ws / cloudflare / a port, or a fallback protocol: ${PROTOS.join(' ')})`);
        if (m === p) die(`${v}='${m}': a protocol cannot fall back to itself`);
        if (p !== 'vless' && p !== 'trojan') die(`${v}='${m}': ${p.toUpperCase()} has no fallback ability, only VLESS and TROJAN can choose a fallback`);
        FB[p] = m;
      } else {
        die(`${v}='${m}' is invalid (expected: ws / cloudflare / a port / a protocol name, comma separated, or empty to disable)`);
      }
    }
  }
  // cloudflare 模式下 CLOUDFLARE_TUNNEL_TOKEN 填 try = 用 Cloudflare 临时隧道(不需要真正的 Token 和域名)
  TRY_TUNNEL = ACTIVE_MODE === 'cloudflare' && CLOUDFLARE_TUNNEL_TOKEN === 'try';
}

// 2. 把回落关系整理成 Reality 链：得到 ENABLED / HEADS / CHAIN / HPORT / RPORT
function buildChains() {
  for (const [p, t] of Object.entries(FB)) { // 每个协议只能被一个协议回落到
    const T = t.toUpperCase();
    if (PARENT[t]) die(`${T} is the fallback of both ${PARENT[t].toUpperCase()} and ${p.toUpperCase()}, it can only have one`);
    PARENT[t] = p;
  }
  for (const p of PROTOS) { // 链头 = 有 Reality 项(数字 / 协议名)且没被别人回落到的协议；只用 ws / cloudflare 的协议不进链
    const hasReality = !!(NPORT[p] || FB[p]);
    if (SHARED.includes(p) || hasReality || PARENT[p]) ENABLED.push(p);
    if (hasReality && !PARENT[p]) HEADS.push(p);
  }
  for (const h of HEADS) { // 顺着回落走到链尾，端口取链尾的数字
    let q = h;
    CHAIN[h] = [h];
    while (FB[q]) { q = FB[q]; CHAIN[h].push(q); }
    if (!NPORT[q]) die(`The chain from ${h.toUpperCase()} ends at ${q.toUpperCase()}, which needs a port: set ${q.toUpperCase()}_MODE to a port number`);
    HPORT[h] = NPORT[q];
    for (const p of CHAIN[h]) RPORT[p] = HPORT[h];
  }
  XRAY_ON = ENABLED.length > 0 || !!(HY2_PORT || MIXED_PORT || WG_PORT); // 没有任何代理协议时不报错，只跑 Komari 探针
  for (const p of ENABLED) if ((NPORT[p] || FB[p] || PARENT[p]) && !RPORT[p]) die(`${p.toUpperCase()} is part of a fallback loop: the chain needs a head that no protocol falls back to`);
}

// 3. 前置入口：是否需要、监听哪个端口、是否与某条 Reality 链共用
function planFront() {
  if (!ACTIVE_MODE && !PORT) return; // ws / cloudflare 模式，或者只填了 PORT(只提供订阅服务)
  FRONT_ON = true;
  // cloudflare 先用 8000(之后从 cloudflared 日志读到隧道的回源端口再覆盖)；其它(ws / 只回落)用 PORT，留空 8000
  const fp = ACTIVE_MODE === 'cloudflare' ? DEFAULT_FRONT_PORT : (PORT || DEFAULT_FRONT_PORT);
  if (!validPort(String(fp))) die(`PORT='${PORT}' is not a valid port`);
  FRONT_PORT = +fp;
  if (!PORT || ACTIVE_MODE === 'cloudflare') return;
  // PORT 与某条 Reality 链端口相同：共用这个端口，Reality 认不出的流量转给本机前置入口(带 TLS，所以有 ws 没有 ws 都行)
  if (HEADS.some((p) => HPORT[p] === FRONT_PORT)) SHARE_FRONT = true;
}

// 4. 端口检查：各 TCP 监听端口(Reality 链头 + 前置入口 + Mixed)互不重复，且不占用 Shadowsocks 内部端口 40004 / 40005
function checkPorts() {
  const ports = HEADS.map((p) => HPORT[p]);
  if (FRONT_ON && !SHARE_FRONT) ports.push(FRONT_PORT);
  if (MIXED_PORT) ports.push(MIXED_PORT);
  const dup = ports.find((x, i) => ports.indexOf(x) !== i);
  if (dup !== undefined) die(`Port ${dup} is used more than once: every Reality chain, the ws / cloudflare group (PORT) and MIXED_MODE need different TCP ports`);
  const bad = ports.find((q) => q === SS_IPORT || q === SS_WS_IPORT);
  if (bad !== undefined) die(`Port ${bad} conflicts with the internal ports 40004 / 40005 used by Shadowsocks`);
}

// ========== TLS 证书(供 ws / Hysteria2 使用) ==========
// 脚本不申请证书。CERT_HOST 是域名且脚本目录下有 $CERT_HOST.crt / $CERT_HOST.key，并且证书可信
// (私钥配对、在有效期内、系统信任的 CA 签发、包含该域名) -> 直接使用，链接不跳过校验；否则用自签证书
const IP_RE = /^[0-9]{1,3}(\.[0-9]{1,3}){3}$/;
let CERT_FILE = '', KEY_FILE = '', TLS_SERVER_NAME = '', TLS_INSECURE = true, TLS_PCS = '';

// 最小的 DER 编码器：只够生成一张自签 X.509 证书
const D = {
  len: (n) => (n < 128 ? Buffer.from([n]) : n < 256 ? Buffer.from([0x81, n]) : Buffer.from([0x82, n >> 8, n & 255])),
  tlv: (tag, ...c) => { const body = Buffer.concat(c); return Buffer.concat([Buffer.from([tag]), D.len(body.length), body]); },
  seq: (...c) => D.tlv(0x30, ...c),
  int: (buf) => D.tlv(0x02, buf[0] & 0x80 ? Buffer.concat([Buffer.from([0]), buf]) : buf),
  oid: (s) => {
    const a = s.split('.').map(Number), bytes = [a[0] * 40 + a[1]];
    for (const n of a.slice(2)) { const t = [n & 127]; for (let v = n >> 7; v; v >>= 7) t.unshift((v & 127) | 128); bytes.push(...t); }
    return D.tlv(0x06, Buffer.from(bytes));
  },
  utc: (d) => D.tlv(0x17, Buffer.from(d.toISOString().replace(/^\d\d(\d\d)-(\d\d)-(\d\d)T(\d\d):(\d\d):(\d\d).*$/, '$1$2$3$4$5$6Z'))),
};

// 生成自签证书(RSA 2048，10 年)；已有且 30 天内不过期就复用，否则每次重启证书哈希都变，已导入的订阅会失效
function generateSelfSignedCert(cn) {
  const dir = path.join(BASE_DIR, '.selfsigned');
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  CERT_FILE = path.join(dir, `${cn}.crt`); KEY_FILE = path.join(dir, `${cn}.key`);
  if (nonEmpty(CERT_FILE) && nonEmpty(KEY_FILE)) {
    try { if (Date.parse(new X509Certificate(fs.readFileSync(CERT_FILE)).validTo) - Date.now() > 30 * 86400e3) return; } catch { /* 重新生成 */ }
  }
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const name = D.seq(D.tlv(0x31, D.seq(D.oid('2.5.4.3'), D.tlv(0x0c, Buffer.from(cn)))));
  const sigAlg = D.seq(D.oid('1.2.840.113549.1.1.11'), D.tlv(0x05));
  const serial = crypto.randomBytes(16); serial[0] = (serial[0] & 0x7f) || 1;
  const san = D.tlv(0xa3, D.seq(D.seq(D.oid('2.5.29.17'), D.tlv(0x04, D.seq(D.tlv(0x82, Buffer.from(cn)), D.tlv(0x82, Buffer.from('localhost')))))));
  const tbs = D.seq(
    D.tlv(0xa0, D.int(Buffer.from([2]))), D.int(serial), sigAlg, name,
    D.seq(D.utc(new Date(Date.now() - 86400e3)), D.utc(new Date(Date.now() + 3650 * 86400e3))), name,
    publicKey.export({ type: 'spki', format: 'der' }), san,
  );
  const cert = D.seq(tbs, sigAlg, D.tlv(0x03, Buffer.concat([Buffer.from([0]), crypto.sign('sha256', tbs, privateKey)])));
  fs.writeFileSync(CERT_FILE, `-----BEGIN CERTIFICATE-----\n${b64(cert).match(/.{1,64}/g).join('\n')}\n-----END CERTIFICATE-----\n`);
  fs.writeFileSync(KEY_FILE, privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });
}

// 校验证书链：叶子证书含域名，沿中间证书逐级验签，最终落在系统信任的根证书上；返回空串表示可信，否则返回原因
function verifyChain(certs, host) {
  const leaf = certs[0];
  if (!leaf.checkHost(host)) return 'hostname mismatch';
  const roots = (tls.getCACertificates ? tls.getCACertificates('default') : tls.rootCertificates).map((p) => new X509Certificate(p)); // Node 22.15 以下只能用内置的根证书列表
  const valid = (c) => Date.now() >= Date.parse(c.validFrom) && Date.now() <= Date.parse(c.validTo);
  const signedBy = (c, i) => c.checkIssued(i) && c.verify(i.publicKey);
  let cur = leaf;
  for (let depth = 0; depth < 8; depth++) {
    if (!valid(cur)) return 'certificate expired or not yet valid';
    if (roots.some((r) => r.fingerprint256 === cur.fingerprint256 || (valid(r) && signedBy(cur, r)))) return '';
    cur = certs.slice(1).find((i) => i !== cur && i.ca && signedBy(cur, i));
    if (!cur) return 'issuer is not trusted';
  }
  return 'chain too long';
}

// 检查 CERT_HOST 的证书是否可信，可信则写入 CERT_FILE / KEY_FILE
function trustedCertForHost(host) {
  const crt = path.join(BASE_DIR, `${host}.crt`), key = path.join(BASE_DIR, `${host}.key`);
  if (!nonEmpty(crt) || !nonEmpty(key)) return false;
  let certs;
  try {
    certs = (fs.readFileSync(crt, 'utf8').match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g) || []).map((p) => new X509Certificate(p));
    if (!certs.length) throw new Error('no certificate found');
    if (!certs[0].checkPrivateKey(crypto.createPrivateKey(fs.readFileSync(key)))) { console.error(`[TLS] ${crt} and ${key} do not match`); return false; }
  } catch (e) { console.error(`[TLS] Cannot read ${crt} / ${key}: ${e.message}`); return false; }
  const why = verifyChain(certs, host);
  if (why) { console.error(`[TLS] ${crt} is not a trusted certificate for ${host}: ${why}`); return false; }
  CERT_FILE = crt; KEY_FILE = key;
  return true;
}

function setupTls() {
  TLS_SERVER_NAME = CERT_HOST || 'www.nazhumi.com';
  TLS_INSECURE = !(CERT_HOST && !IP_RE.test(CERT_HOST) && trustedCertForHost(CERT_HOST));
  if (TLS_INSECURE) {
    console.error(`[TLS] No trusted certificate available (put one at ${BASE_DIR}/<CERT_HOST>.crt and .key), using self-signed certificate`);
    generateSelfSignedCert(TLS_SERVER_NAME);
    // 新版 Xray 客户端已移除 allowInsecure，自签证书改用证书哈希固定(链接里的 pcs)
    TLS_PCS = new X509Certificate(fs.readFileSync(CERT_FILE)).fingerprint256.replace(/:/g, '').toLowerCase();
  }
  console.log(`[TLS] Server name: ${TLS_SERVER_NAME}, insecure: ${TLS_INSECURE ? 1 : 0}, cert: ${CERT_FILE}, key: ${KEY_FILE}`);
}

// ========== 密钥 ==========
// X25519：固定的 PKCS8 DER 头 + 32 字节私钥，推导出配对的公钥(Reality 和 WireGuard 共用)
const x25519Public = (priv32) => crypto.createPublicKey(crypto.createPrivateKey({
  key: Buffer.concat([Buffer.from('302e020100300506032b656e04220420', 'hex'), priv32]), format: 'der', type: 'pkcs8',
})).export({ type: 'spki', format: 'der' }).subarray(-32);

// 私钥由 UUID 派生(SHA-256 加用途标签，再按 X25519 规则整理)：同一个 UUID 永远得到同一组密钥，不落盘；enc 是 base64 / base64url
function deriveKey(label, enc) {
  const priv = crypto.createHash('sha256').update(`${label}:${UUID}`).digest();
  priv[0] &= 248; priv[31] = (priv[31] & 127) | 64;
  return [priv.toString(enc), Buffer.from(x25519Public(priv)).toString(enc)];
}

// ========== 链接里的连接地址(PUBLIC_IP) ==========
// CERT_HOST 填 IP -> 直接用；填域名或留空 -> 探测公网 IPv4，域名解析结果包含它(域名指向本服务器)时改用域名
let PUBLIC_IP = '';
const TRACE_URL = 'https://one.one.one.one/cdn-cgi/trace';

async function resolvePublicAddr() {
  if (IP_RE.test(CERT_HOST)) {
    PUBLIC_IP = CERT_HOST;
  } else {
    const r = await request(TRACE_URL, { family: 4, timeout: 5000 }).catch(() => null); // 只取 IPv4：IPv6 地址直接拼进 host:port 会让链接失效
    PUBLIC_IP = ((r && r.body.match(/^ip=(.*)$/m)) || [, ''])[1].trim();
    if (CERT_HOST && PUBLIC_IP) {
      const ips = await dns.promises.lookup(CERT_HOST, { family: 4, all: true }).then((l) => l.map((x) => x.address)).catch(() => []);
      if (ips.includes(PUBLIC_IP)) { console.log(`[NET] ${CERT_HOST} points to this server, using it instead of the IP`); PUBLIC_IP = CERT_HOST; }
    }
  }
  if (!PUBLIC_IP) console.error('[NET] Cannot determine the public address, links will be invalid (set CERT_HOST)');
  console.log(`[NET] Address in links: ${PUBLIC_IP}`);
}

// ========== Xray 配置 ==========
let REALITY_PRIVATE_KEY = '', REALITY_PUBLIC_KEY = '', VLESS_FLOW = '', IPV6_AVAILABLE = false;
let WG_SERVER_PRIVATE = '', WG_SERVER_PUBLIC = '', WG_CLIENT_PRIVATE = '', WG_CLIENT_PUBLIC = '';
const SNIFFING = { enabled: true, destOverride: ['http', 'tls', 'quic'], routeOnly: true }; // 只用于路由匹配，不改写目标地址

const streamTcp = () => ({ network: 'tcp', security: 'none' });
const streamWs = (p) => ({ network: 'ws', security: 'none', wsSettings: { path: p } });
const streamReality = (dest = 'www.iij.ad.jp:443', sni = 'www.iij.ad.jp') => ({
  network: 'tcp', security: 'reality',
  realitySettings: { show: false, dest, xver: 0, serverNames: [sni], privateKey: REALITY_PRIVATE_KEY, shortIds: ['cdcf853c'] },
});
const streamTls = (network, alpn, extra = {}) => ({
  network, security: 'tls',
  tlsSettings: { serverName: TLS_SERVER_NAME, alpn: [alpn], certificates: [{ certificateFile: CERT_FILE, keyFile: KEY_FILE }] },
  ...extra,
});

function protoSettings(p, fallbacks, flow) {
  const fb = fallbacks ? { fallbacks } : {};
  switch (p) {
    case 'vless': return { clients: [{ id: UUID, email: UUID, ...(flow ? { flow } : {}) }], decryption: 'none', ...fb };
    case 'vmess': return { clients: [{ id: UUID, email: UUID }] };
    case 'trojan': return { clients: [{ password: UUID, email: UUID }], ...fb };
    case 'shadowsocks': return { method: 'aes-256-gcm', password: UUID, network: 'tcp' };
  }
}

const inbound = (tag, listen, port, protocol, settings, streamSettings) => ({ tag, listen, port, protocol, settings, streamSettings, sniffing: SNIFFING });

function buildConfig() {
  const inb = [];
  if (FRONT_ON) {
    // 前置入口：按 HTTP 路径把 ws 流量回落给各内部 ws 入口，其余请求回落给本机内置的 HTTP 服务；ws 带 TLS，cloudflare 和只回落是明文。
    // 与 Reality 共用端口时只听内部 socket，由 Reality 转进来。前置入口本身也是一个 VLESS 入口
    // ws 入口用 wsInternal(带 -ws 后缀)，和同一协议的 Reality 链入口互不冲突
    const fb = [];
    for (const p of SHARED) {
      const i = wsInternal(p);
      fb.push({ path: WS_PATH[p], dest: i.dest, xver: 0 });
      inb.push(inbound(`${p}-ws-in`, i.listen, i.port, p, protoSettings(p), streamWs(WS_PATH[p])));
    }
    fb.push({ dest: WEB_SOCK, xver: 0 });
    const [listen, port] = SHARE_FRONT ? [FRONT_SOCK, undefined] : ['::', FRONT_PORT];
    inb.push(inbound('front-in', listen, port, 'vless', protoSettings('vless', fb), FRONT_TLS ? streamTls('tcp', 'http/1.1') : streamTcp()));
  }
  for (const h of HEADS) { // Reality 链：链头监听自己的端口并套 Reality；被回落到的协议监听 127.0.0.1 内部端口
    for (const p of CHAIN[h]) {
      const fb = FB[p] ? [{ dest: internal(FB[p]).dest, xver: 0 }] : undefined;
      if (p !== h) { const i = internal(p); inb.push(inbound(`${p}-in`, i.listen, i.port, p, protoSettings(p, fb), streamTcp())); continue; }
      const stream = SHARE_FRONT && HPORT[h] === FRONT_PORT ? streamReality(FRONT_SOCK, TLS_SERVER_NAME) : streamReality();
      inb.push(inbound(`${p}-in`, '::', HPORT[h], p, protoSettings(p, fb, p === 'vless' ? VLESS_FLOW : ''), stream));
    }
  }
  if (HY2_PORT) inb.push(inbound('hysteria2-in', '::', HY2_PORT, 'hysteria', { version: 2, clients: [{ auth: UUID, email: UUID }] }, streamTls('hysteria', 'h3', { hysteriaSettings: { version: 2 } })));
  if (MIXED_PORT) inb.push(inbound('mixed-in', '::', MIXED_PORT, 'socks', { auth: 'password', accounts: [{ user: UUID, pass: UUID }], udp: false }, streamTcp()));
  if (WG_PORT) inb.push(inbound('wireguard-in', '::', WG_PORT, 'wireguard', { secretKey: WG_SERVER_PRIVATE, peers: [{ publicKey: WG_CLIENT_PUBLIC, allowedIPs: [WG_CLIENT_ADDR] }], mtu: 1420 }));
  return {
    log: { loglevel: 'warning' },
    dns: { servers: ['https+local://1.1.1.1/dns-query'], queryStrategy: 'UseIPv4' },
    inbounds: inb,
    outbounds: [{ tag: 'direct', protocol: 'freedom' }, { tag: 'block', protocol: 'blackhole' }],
    routing: {
      domainStrategy: 'IPIfNonMatch',
      rules: [
        { type: 'field', ip: ['geoip:private'], outboundTag: 'direct' },
        ...(IPV6_AVAILABLE ? [] : [{ type: 'field', ip: ['::/0'], outboundTag: 'block' }]), // 无 IPv6 出口时拒绝 IPv6 目标，让客户端立即回退 IPv4
        { type: 'field', domain: ['geosite:cn', 'geosite:category-ads-all'], outboundTag: 'block' },
        { type: 'field', ip: ['geoip:cn'], outboundTag: 'block' },
      ],
    },
  };
}

// ========== 订阅链接 ==========
let SS_USERINFO = '', CLOUDFLARE_TUNNEL_HOSTNAME = '';

// reality 链接(VMess / SS 也用 URI 格式，客户端要能当作 Reality 节点导入)；name 是节点名(同一协议有两条链接时带后缀)
function realityLink(proto, port, name) {
  const sni = SHARE_FRONT && port === FRONT_PORT ? TLS_SERVER_NAME : 'www.iij.ad.jp';
  const pre = { vless: `encryption=none${VLESS_FLOW ? `&flow=${VLESS_FLOW}` : ''}&`, vmess: 'encryption=auto&' }[proto] || '';
  const rq = `security=reality&sni=${sni}&fp=chrome&pbk=${REALITY_PUBLIC_KEY}&type=tcp&sid=cdcf853c`;
  return `${proto === 'shadowsocks' ? 'ss' : proto}://${proto === 'shadowsocks' ? SS_USERINFO : UUID}@${PUBLIC_IP}:${port}?${pre}${rq}#${urlencode(name)}`;
}

// ws / cloudflare 链接的共同参数：cloudflare 连 CLOUDFLARE_IP(没设置就连探测到的隧道域名):443；ws 连 PUBLIC_IP:FRONT_PORT，自签证书用 pcs 固定
function wsParams() {
  if (ACTIVE_MODE === 'cloudflare') return { addr: CLOUDFLARE_IP || CLOUDFLARE_TUNNEL_HOSTNAME, port: 443, host: CLOUDFLARE_TUNNEL_HOSTNAME, iq: '', vmInsecure: 0, vmExtra: null, vmPcs: '' };
  const ins = TLS_INSECURE ? 1 : 0;
  return {
    addr: PUBLIC_IP, port: FRONT_PORT, host: TLS_SERVER_NAME, vmInsecure: ins, vmPcs: TLS_PCS,
    vmExtra: { allowInsecure: ins, verify_cert: !TLS_INSECURE }, iq: TLS_INSECURE ? `&allowInsecure=1&pcs=${TLS_PCS}` : '',
  };
}

// ws / cloudflare 链接
function wsLink(proto, WS, name) {
  const ne = urlencode(name);
  const p = WS_PATH[proto], enc = p.replace(/\//g, '%2F');
  if (ACTIVE_MODE === 'cloudflare' && (!CLOUDFLARE_TUNNEL_HOSTNAME || !CLOUDFLARE_TUNNEL_TOKEN)) {
    console.error(`[MODE] cloudflare mode needs CLOUDFLARE_TUNNEL_TOKEN (set it to 'try' for a quick tunnel) and a tunnel hostname found in the cloudflared log, no ${proto} link generated`);
    return '';
  }
  const q = `sni=${WS.host}&fp=chrome&type=ws&host=${WS.host}&path=${enc}${WS.iq}#${ne}`;
  switch (proto) {
    case 'vless': return `vless://${UUID}@${WS.addr}:${WS.port}?encryption=none&security=tls&${q}`;
    case 'trojan': return `trojan://${UUID}@${WS.addr}:${WS.port}?security=tls&${q}`;
    case 'vmess': { // ?ed=2560 为 0-RTT early data，Xray 服务端自动识别
      const ed = ACTIVE_MODE === 'cloudflare' ? '?ed=2560' : '';
      return `vmess://${b64(JSON.stringify({
        v: '2', ps: name, add: WS.addr, port: String(WS.port), id: UUID, aid: '0', scy: 'none', net: 'ws', type: 'none',
        host: WS.host, path: p + ed, tls: 'tls', sni: WS.host, alpn: '', fp: '', insecure: String(WS.vmInsecure), ...(WS.vmExtra || {}), vcn: '', pcs: WS.vmPcs,
      }))}`;
    }
    case 'shadowsocks': { // v2ray-plugin 无法跳过证书校验，自签证书下该节点连不上，不输出
      if (ACTIVE_MODE === 'ws' && TLS_INSECURE) {
        console.error(`[MODE] ws mode: Shadowsocks (v2ray-plugin) needs a trusted certificate, put one at ${BASE_DIR}/<CERT_HOST>.crt and .key. No SS link generated`);
        return '';
      }
      const plugin = `v2ray-plugin;tls;host=${WS.host};path=${p};mux=0`.replace(/;/g, '%3B').replace(/=/g, '%3D').replace(/\//g, '%2F');
      return `ss://${SS_USERINFO}@${WS.addr}:${WS.port}/?plugin=${plugin}#${ne}`;
    }
  }
}

// 一个协议可能输出两条链接(Reality + ws / cloudflare)，两条都有时节点名加后缀区分
function generateNodes(proto, WS) {
  const both = !!RPORT[proto] && SHARED.includes(proto);
  const out = [];
  if (RPORT[proto]) out.push(realityLink(proto, RPORT[proto], both ? `${NAME}-reality` : NAME));
  if (SHARED.includes(proto)) out.push(wsLink(proto, WS, both ? `${NAME}-${ACTIVE_MODE}` : NAME));
  return out.filter(Boolean);
}

const hy2Link = () => `hysteria2://${UUID}@${PUBLIC_IP}:${HY2_PORT}/?sni=${TLS_SERVER_NAME}${TLS_INSECURE ? '&insecure=1' : ''}#${NAME_ENC}`;
const mixedLinks = () => `socks5://${UUID}:${UUID}@${PUBLIC_IP}:${MIXED_PORT}#${NAME_ENC}\nhttp://${UUID}:${UUID}@${PUBLIC_IP}:${MIXED_PORT}#${NAME_ENC}`;
const wgLink = () => `wireguard://${urlencode(WG_CLIENT_PRIVATE)}@${PUBLIC_IP}:${WG_PORT}?publickey=${urlencode(WG_SERVER_PUBLIC)}&address=${urlencode(WG_CLIENT_ADDR)}&mtu=1420#${NAME_ENC}`;
const wgConf = () => `[Interface]\nPrivateKey = ${WG_CLIENT_PRIVATE}\nAddress = ${WG_CLIENT_ADDR}\nDNS = 1.1.1.1\nMTU = 1420\n\n[Peer]\nPublicKey = ${WG_SERVER_PUBLIC}\nEndpoint = ${PUBLIC_IP}:${WG_PORT}\nAllowedIPs = 0.0.0.0/0, ::/0\nPersistentKeepalive = 25\n`;

// ========== 内置 HTTP 服务(订阅 + 回落) ==========
// 监听 abstract unix socket(WEB_SOCK，不占 TCP 端口)，由前置入口回落过来：GET /UUID 返回 base64 订阅；其它路径转给 WEB_DEST(没有就返回 404)
function startWeb(subBody) {
  const [dh, dp] = WEB_DEST ? [WEB_DEST.split(':')[0], +WEB_DEST.split(':')[1]] : [];
  http.createServer((req, res) => {
    const pathname = req.url.split('?')[0];
    console.log(`[WEB] ${req.method} ${pathname === `/${UUID}` ? '/UUID' : pathname}`); // 请求到了内置服务就会打印一行，用来判断问题出在前面的 Xray 还是客户端
    if ((req.method === 'GET' || req.method === 'HEAD') && pathname === `/${UUID}`) {
      res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store' });
      return res.end(req.method === 'HEAD' ? undefined : subBody);
    }
    if (!WEB_DEST) { res.writeHead(404, { 'Content-Type': 'text/plain' }); return res.end('Not Found'); }
    const up = http.request({ host: dh, port: dp, path: req.url, method: req.method, headers: req.headers }, (r) => { res.writeHead(r.statusCode, r.headers); r.pipe(res); });
    up.on('error', () => { res.writeHead(502); res.end(); });
    req.pipe(up);
  }).on('error', (e) => console.error(`[WEB] HTTP service failed: ${e.message}`)).listen(`\0${WEB_SOCK.slice(1)}`); // Node 里 abstract socket 以 \0 开头，Xray 里以 @ 开头
}

// ========== 外部程序 ==========
// 下载 GitHub release 里的二进制到脚本目录并加执行权限
async function fetchBin(file, url) {
  const bin = path.join(BASE_DIR, file);
  if (!await dl(bin, url)) process.exit(1);
  fs.chmodSync(bin, 0o755);
  return bin;
}

// Komari 探针：KOMARI_ENDPOINT 和 KOMARI_TOKEN 都填了才启用。有代理协议时后台运行；没有时脚本只当 Komari 启动脚本，前台运行
async function startKomari() {
  await killPrevious('komari-agent', 'KOMARI');
  const bin = await fetchBin('komari-agent', `https://github.com/komari-monitor/komari-agent/releases/latest/download/komari-agent-linux-${ARCH}`);
  const agentEnv = { AGENT_ENDPOINT: KOMARI_ENDPOINT, AGENT_TOKEN: KOMARI_TOKEN }; // 只传给这一个进程，ps 看不到
  if (XRAY_ON) {
    spawnBg(bin, [], path.join(BASE_DIR, 'komari-agent.log'), agentEnv);
    return console.log(`[KOMARI] Agent started, reporting to ${KOMARI_ENDPOINT}`);
  }
  console.log(`[KOMARI] No proxy protocol enabled, running the agent only, reporting to ${KOMARI_ENDPOINT}`);
  const child = cp.spawn(bin, [], { env: { ...process.env, ...GO_ENV, ...agentEnv }, stdio: 'inherit' });
  children.push(child);
  child.on('exit', (code) => process.exit(code ?? 1));
  await new Promise(() => {}); // 一直运行，直到 agent 退出
}

// 取 cloudflared 日志里下发的 ingress 规则：第一条「有具体域名(不含 *)、Service 是 http://localhost:端口 或 127.0.0.1:端口」的规则
function parseIngress(text) {
  const m = text.split('\n').filter((l) => l.includes('Updated to new configuration')).pop()?.match(/config="(.*)" version=/);
  if (!m) return null;
  let cfg;
  try { cfg = JSON.parse(m[1].replace(/\\"/g, '"')); } catch { return null; } // 日志里的引号带反斜杠，先还原
  for (const r of cfg.ingress || []) {
    const sm = r.hostname && !r.hostname.includes('*') && /^http:\/\/(?:localhost|127\.0\.0\.1):(\d+)$/.exec(r.service || '');
    if (sm) return { hostname: r.hostname, port: sm[1] };
  }
  return null;
}

// cloudflare 模式：用 Token 跑固定隧道；Token 填 try 时用 Cloudflare 临时隧道(每次启动域名都会变)。域名和回源端口都从日志里取
async function startCloudflared() {
  await killPrevious('cloudflared', 'CF');
  const bin = await fetchBin('cloudflared', `https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-${ARCH}`);
  const log = path.join(BASE_DIR, 'cloudflared.log');
  cp.spawnSync(bin, ['--version'], { stdio: 'inherit' });

  if (TRY_TUNNEL) {
    spawnBg(bin, ['--no-autoupdate', 'tunnel', '--url', `http://localhost:${FRONT_PORT}`], log);
    for (let i = 0; i < 30 && !CLOUDFLARE_TUNNEL_HOSTNAME; i++) {
      CLOUDFLARE_TUNNEL_HOSTNAME = [...readLog(log).matchAll(/https:\/\/([a-z0-9-]+\.trycloudflare\.com)/g)].map((m) => m[1]).find((h) => !h.startsWith('api.')) || '';
      if (!CLOUDFLARE_TUNNEL_HOSTNAME) await sleep(1000);
    }
    if (CLOUDFLARE_TUNNEL_HOSTNAME) console.log(`[CF] Quick tunnel hostname from log: ${CLOUDFLARE_TUNNEL_HOSTNAME} (service port=${FRONT_PORT})`);
    else console.error(`[CF] Cannot find the trycloudflare.com hostname in ${log}`);
    return;
  }

  spawnBg(bin, ['--no-autoupdate', 'tunnel', 'run'], log, { TUNNEL_TOKEN: CLOUDFLARE_TUNNEL_TOKEN });
  for (let i = 0; i < 30 && !readLog(log).includes('Updated to new configuration'); i++) await sleep(1000);
  const rule = parseIngress(readLog(log));
  if (rule && validPort(rule.port)) {
    CLOUDFLARE_TUNNEL_HOSTNAME = rule.hostname;
    FRONT_PORT = +rule.port;
    checkPorts(); // 端口变了，重新检查是否与 Reality 端口 / 内部保留端口冲突
    console.log(`[CF] From cloudflared log: hostname=${CLOUDFLARE_TUNNEL_HOSTNAME}, tunnel service port=${FRONT_PORT}`);
  } else {
    console.error(`[CF] Cannot read hostname / port from ${log} (the tunnel needs a Public hostname without * and a Service like http://localhost:PORT)`);
  }
}

// ========== 主流程 ==========
async function main() {
  parseModes();
  buildChains();
  planFront();
  FRONT_TLS = ACTIVE_MODE === 'ws' || SHARE_FRONT; // 前置入口是否带 TLS：ws 模式，或者和 Reality 共用端口(Reality 只能把 TLS 流量转给它)
  checkPorts();

  if (ENABLED.length) console.log(`[MODE] enabled=${ENABLED.join(' ')}`);
  if (ACTIVE_MODE) console.log(`[MODE] port ${FRONT_PORT}: ${ACTIVE_MODE} (${SHARED.join(' ')})${SHARE_FRONT ? ' shared with reality' : ''}`);
  for (const p of HEADS) console.log(`[MODE] port ${HPORT[p]}: reality (${CHAIN[p].join(' -> ')})`);
  VLESS_FLOW = HEADS.includes('vless') ? 'xtls-rprx-vision' : ''; // 流控 Vision 仅 VLESS 作为 Reality 链头时支持

  const KM_ON = !!(KOMARI_ENDPOINT && KOMARI_TOKEN);
  if (!XRAY_ON && !KM_ON) die('Nothing to run: set a protocol *_MODE / HYSTERIA2_MODE / MIXED_MODE / WIREGUARD_MODE, or KOMARI_ENDPOINT + KOMARI_TOKEN');
  if (KM_ON) await startKomari();

  if (HEADS.length) {
    [REALITY_PRIVATE_KEY, REALITY_PUBLIC_KEY] = deriveKey('reality', 'base64url');
    console.log(`[REALITY] Private key: ${REALITY_PRIVATE_KEY}\n[REALITY] Public key: ${REALITY_PUBLIC_KEY}`);
  }
  if (WG_PORT) { // WireGuard：服务端、客户端各一把私钥(标准 base64)
    [WG_SERVER_PRIVATE, WG_SERVER_PUBLIC] = deriveKey('wg-server', 'base64');
    [WG_CLIENT_PRIVATE, WG_CLIENT_PUBLIC] = deriveKey('wg-client', 'base64');
  }
  SS_USERINFO = b64url(`aes-256-gcm:${UUID}`);

  if (ACTIVE_MODE !== 'cloudflare' || HEADS.length || HY2_PORT || MIXED_PORT || WG_PORT) await resolvePublicAddr();
  IPV6_AVAILABLE = await request(TRACE_URL, { family: 6, timeout: 5000 }).then(() => true, () => false);
  console.log(IPV6_AVAILABLE ? '[NET] IPv6 egress: available' : '[NET] IPv6 egress: unavailable, blocking IPv6 destinations');
  if (FRONT_TLS || HY2_PORT) setupTls();
  if (ACTIVE_MODE === 'cloudflare' && CLOUDFLARE_TUNNEL_TOKEN) await startCloudflared();

  // ---- Xray ----
  const xrayDir = path.join(BASE_DIR, 'xray'), xrayBin = path.join(xrayDir, 'xray'), xrayConf = path.join(xrayDir, 'config.json'), zipFile = path.join(BASE_DIR, 'xray.zip');
  fs.mkdirSync(xrayDir, { recursive: true });
  if (!await dl(zipFile, `https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-${ARCH === 'amd64' ? '64' : 'arm64-v8a'}.zip`)) process.exit(1);
  await unzip(zipFile, xrayDir);
  fs.rmSync(zipFile, { force: true });
  try { fs.chmodSync(xrayBin, 0o755); } catch { /* 下面统一检查 */ }
  if (!nonEmpty(xrayBin)) { console.error(`[XRAY] Binary not found after extraction: ${xrayBin}`); process.exit(1); }
  const xrayEnv = { ...process.env, ...GO_ENV, XRAY_LOCATION_ASSET: xrayDir }; // geoip.dat / geosite.dat 随发行包解压在同一目录
  const xray = (args, opts = {}) => cp.spawnSync(xrayBin, args, { stdio: 'inherit', env: xrayEnv, ...opts });
  xray(['version']);

  fs.writeFileSync(xrayConf, '', { mode: 0o600 }); // 先收紧权限再写入(里面有 UUID 和 Reality 私钥)
  fs.chmodSync(xrayConf, 0o600);
  fs.writeFileSync(xrayConf, `${JSON.stringify(buildConfig(), null, 2)}\n`);
  if (xray(['run', '-test', '-c', xrayConf]).status !== 0) { console.error('[XRAY] Config test failed, aborting'); process.exit(1); }

  // ---- 输出订阅：每行一个原始链接，末尾再给一份合并后的 base64 ----
  const WS = ACTIVE_MODE ? wsParams() : null;
  const nodes = ENABLED.flatMap((p) => generateNodes(p, WS));
  if (HY2_PORT) nodes.push(hy2Link());
  if (MIXED_PORT) nodes.push(mixedLinks());
  if (WG_PORT) nodes.push(wgLink());
  const allNodes = nodes.filter(Boolean).map((n) => `${n}\n`).join('');
  console.log(`\n=== Nodes ===\n${allNodes}\n=== Subscription (base64) ===\n${b64(allNodes)}\n`);
  if (WG_PORT) console.log(`\n=== WireGuard config (wg-quick) ===\n${wgConf()}`);
  if (FRONT_ON) { // 订阅地址：cloudflare 走隧道域名；ws 走 TLS；只填 PORT 时是明文 HTTP
    startWeb(b64(allNodes));
    const base = ACTIVE_MODE === 'cloudflare' ? (CLOUDFLARE_TUNNEL_HOSTNAME && `https://${CLOUDFLARE_TUNNEL_HOSTNAME}`) : `${FRONT_TLS ? 'https' : 'http'}://${PUBLIC_IP}:${FRONT_PORT}`;
    if (base) console.log(`\n=== Subscription URL ===\n${base}/${UUID}${FRONT_TLS && TLS_INSECURE ? '\n(自签证书：客户端需要允许不校验证书)' : ''}\n`);
  }

  try { bi('v8').setFlagsFromString('--expose-gc'); bi('vm').runInNewContext('gc')(); } catch { /* 没有就算了 */ } // 后面脚本只负责看着子进程，先把前面用过的堆回收掉
  const proc = cp.spawn(xrayBin, ['run', '-c', xrayConf], { stdio: 'inherit', env: xrayEnv });
  children.push(proc);
  proc.on('exit', (code) => process.exit(code ?? 1));
}

main().catch((e) => { console.error(e); process.exit(1); });
