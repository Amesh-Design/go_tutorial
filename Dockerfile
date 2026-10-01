# ==========================================
# Multi-stage Dockerfile for Go Backend API
# ==========================================

# 1. Build Stage
FROM golang:1.23-alpine AS builder

WORKDIR /app

# Download dependencies first (cached layer)
COPY go.mod go.sum ./
RUN go mod download

# Copy source code and compile statically linked binary for Linux
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o server ./cmd/api

# 2. Production Stage (ultra-lightweight ~20MB container)
FROM alpine:latest

# Install root CA certificates for HTTPS/SSL connections (e.g. Neon PostgreSQL & website scanner)
RUN apk --no-cache add ca-certificates tzdata

WORKDIR /app

# Copy binary from builder stage
COPY --from=builder /app/server .

# Render dynamically sets PORT (defaults to 8080 locally)
ENV PORT=8080
ENV APP_ENV=production

EXPOSE 8080

CMD ["./server"]
