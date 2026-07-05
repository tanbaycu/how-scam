FROM golang:1.21-bookworm

# Install Chromium and system libraries
RUN apt-get update && apt-get install -y \
    chromium \
    chromium-driver \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY go.mod ./
RUN go mod download

COPY main.go detector.go takedown.go ./

RUN go build -o scam-guardian main.go detector.go takedown.go

ENTRYPOINT ["./scam-guardian"]
