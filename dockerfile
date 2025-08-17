# Build stage
# FROM golang:1.23-alpine@sha256:b538dc78c7e5dd860fcebc49c70716a38c8263b8a3b7b5c4b8e9c7a3f7a1b8c2 AS build-env
FROM golang:1.23-alpine AS builder
# Install build dependencies
RUN apk update && apk add --no-cache build-base libpcap-dev git tzdata

WORKDIR /app

# Copy dependency files first for better caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source and build
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags='-w -s -extldflags "-static"' \
    -a -installsuffix cgo \
    -o naabum8 .

# Production stage - Hardened Alpine
# FROM alpine:3.20@sha256:77726ef6b57ddf65bb551896826ec38bc3e53f75cdde31354fbffb4f25238ebd
FROM alpine:3.20
# Security hardening - Remove unnecessary packages and create secure environment
RUN apk upgrade --no-cache && \
    apk add --no-cache \
    ca-certificates \
    libpcap \
    nmap \
    nmap-scripts \
    bind-tools \
    tini && \
    # Remove potentially dangerous utilities
    rm -rf /bin/su \
    /bin/mount \
    /bin/umount \
    /sbin/mount* \
    /usr/bin/passwd \
    /usr/bin/chpasswd \
    /usr/sbin/adduser \
    /usr/sbin/deluser \
    /etc/crontabs \
    /var/spool/cron && \
    # Clean package cache
    rm -rf /var/cache/apk/* /tmp/* && \
    # Create secure directories with proper permissions
    mkdir -p /app/data /tmp && \
    chmod 1777 /tmp && \
    chmod 755 /app

# Copy application binary with secure permissions
COPY --from=builder /app/naabum8 /usr/local/bin/naabum8
RUN chmod 755 /usr/local/bin/naabum8

WORKDIR /app

# Use tini as init system for proper signal handling
ENTRYPOINT ["/sbin/tini", "--"]

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD naabum8 help || exit 1

# Default command
CMD ["naabum8", "help"]

# Metadata
LABEL maintainer="i@deifzar.me" \
    version="1.0" \
    description="NaabuM8 - Hardened Network Scanner" \
    security.scan="required-root-privileges"