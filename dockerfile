# Build
FROM golang:1.24.0-alpine AS build-env
RUN apk add --no-cache build-base libpcap-dev
WORKDIR /app
COPY . /app
RUN go mod download
RUN go build .

# Release
FROM alpine:3.21.3
RUN apk upgrade --no-cache \
    && apk add --no-cache nmap libpcap-dev bind-tools ca-certificates nmap-scripts
WORKDIR /app
COPY --from=build-env /app/naabum8 /usr/local/bin/
CMD ["naabum8","help"]