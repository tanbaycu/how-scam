FROM golang:1.21-bookworm AS builder

RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY go.mod ./
RUN go mod download
COPY *.go ./
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o scam-guardian .

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    chromium \
    ca-certificates \
    whois \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/scam-guardian /usr/local/bin/scam-guardian

WORKDIR /app

ENTRYPOINT ["scam-guardian"]
