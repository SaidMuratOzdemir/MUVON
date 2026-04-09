# syntax=docker/dockerfile:1
# Usage:
#   docker build --build-arg SERVICE=muvon -t muvon .
#   docker build --build-arg SERVICE=agent -t muvon-agent .
ARG SERVICE=muvon

# ── Stage 1: Build UI (only needed for muvon) ──────────────────────────────
FROM node:22-alpine AS ui-builder
WORKDIR /app/ui
COPY ui/package.json ui/package-lock.json* ./
RUN npm ci --prefer-offline
COPY ui/ ./
RUN npm run build

# ── Stage 2: Build Go binary ───────────────────────────────────────────────
FROM golang:1.24-alpine AS go-builder
ARG SERVICE
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# Embed UI dist into muvon; agent doesn't need it
COPY --from=ui-builder /app/ui/dist ./frontend/dist
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w" \
    -o /out/${SERVICE} \
    ./cmd/${SERVICE}

# ── Stage 3: Minimal runtime image ────────────────────────────────────────
# Uses root-user distroless so services can bind Unix sockets on shared volumes.
# Container isolation (no shell, minimal OS) still provides strong security.
FROM gcr.io/distroless/static-debian12 AS final
ARG SERVICE
COPY --from=go-builder /out/${SERVICE} /usr/local/bin/app
# TLS cert cache for ACME (agent mounts this as a volume)
VOLUME ["/var/lib/app/tls"]
ENTRYPOINT ["/usr/local/bin/app"]
