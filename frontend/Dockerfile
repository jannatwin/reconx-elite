FROM node:20-alpine AS build

WORKDIR /app

ARG VITE_API_BASE_URL=http://localhost:8000
ENV VITE_API_BASE_URL=${VITE_API_BASE_URL}

# This repository uses npm workspaces (root package-lock.json is authoritative).
COPY package.json package-lock.json ./
COPY frontend/package.json frontend/package.json
RUN npm ci -w reconx-elite-frontend

COPY frontend ./frontend
RUN npm run build -w reconx-elite-frontend

FROM nginx:1.27-alpine

COPY frontend/nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/frontend/dist /usr/share/nginx/html

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
