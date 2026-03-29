ARG IMAGE_REGISTRY=docker.io

FROM ${IMAGE_REGISTRY}/node:22-alpine AS builder
WORKDIR /app
COPY package.json pnpm-lock.yaml ./
RUN corepack enable && pnpm install --frozen-lockfile
COPY . .
RUN pnpm run build

# Optional frontend-only image for local UI development.
EXPOSE 5173
CMD ["pnpm", "run", "dev", "--", "--host", "0.0.0.0", "--port", "5173"]
