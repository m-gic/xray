FROM node:22-alpine
WORKDIR /app
COPY index.js ./
RUN chmod -R a+rwX /app
ENV HOME=/tmp
ENTRYPOINT ["node", "index.js"]
