# xray.js 的运行镜像：脚本只用 Node 内置模块，运行时自己下载 Xray / cloudflared / komari-agent
# amd64 和 arm64 都能用(脚本按 process.arch 选择二进制)
FROM node:22-alpine

WORKDIR /app
COPY index.js ./

# 配置全部走环境变量，例如：
#   VLESS_MODE=8443  PORT=443  CERT_HOST=example.com  UUID=...  NAME=my-node
# 运行时产生的文件都在 /app：xray/ 二进制和配置、.selfsigned/ 自签证书、
# 以及写回 xray.js 里的 UUID。需要持久化就挂载卷到 /app，
# 可信证书放 /app/<CERT_HOST>.crt 和 /app/<CERT_HOST>.key

ENTRYPOINT ["node", "index.js"]
