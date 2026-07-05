# Use Go official Debian Bookworm image
FROM golang:1.21-bookworm

# Install build dependencies, clang, llvm, bpftool and kernel headers
RUN apt-get update && apt-get install -y \
    clang \
    llvm \
    bpftool \
    libbpf-dev \
    gcc-multilib \
    linux-headers-generic \
    dos2unix \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy dependency files
COPY go.mod ./
RUN go mod download

# Copy the rest of the source code
COPY guardian.bpf.c main.go run.sh rules.json ./

# Fix line endings of run.sh in case the file was checked out or saved with CRLF on Windows
RUN dos2unix run.sh && chmod +x run.sh

# Run the agent compiler and daemon
ENTRYPOINT ["./run.sh"]
