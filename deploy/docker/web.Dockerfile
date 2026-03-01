FROM node:22-bookworm AS builder
WORKDIR /app

ARG VITE_API_BASE_URL=http://localhost:8080
ENV VITE_API_BASE_URL=${VITE_API_BASE_URL}

COPY web/package.json ./
RUN npm install

COPY web ./
RUN npm run build

FROM nginx:1.27-alpine
COPY deploy/docker/web.nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=builder /app/dist /usr/share/nginx/html

EXPOSE 80
