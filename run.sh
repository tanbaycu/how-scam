#!/bin/bash
# Startup Script: run.sh
# Author: tanbaycu
# Description: Generates vmlinux.h dynamically from the running host kernel,
#              compiles the eBPF code and Go application, and runs the agent.

set -e

echo "=========================================================="
echo "   kernel-guardian: Dynamic Compilation Bootloader         "
echo "   Author: tanbaycu                                       "
echo "=========================================================="

# 1. Mount debugfs if not mounted (needed for eBPF tracepoints)
if [ ! -d /sys/kernel/debug/tracing ]; then
    echo "[+] Mounting debugfs..."
    mount -t debugfs debugfs /sys/kernel/debug || echo "[!] Warning: Failed to mount debugfs. It might already be mounted or permission denied."
fi

# 2. Generate vmlinux.h from the current running kernel
echo "[+] Generating vmlinux.h from current host kernel..."
if [ -f /sys/kernel/btf/vmlinux ]; then
    bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
    echo "[+] vmlinux.h successfully generated."
else
    echo "[!] CRITICAL: /sys/kernel/btf/vmlinux not found!"
    echo "[!] Your kernel does not have BTF enabled. Cannot generate vmlinux.h."
    echo "[!] Attempting fallback using minimal kernel types..."
    
    # Write a minimal vmlinux.h fallback so compilation doesn't crash if BTF is missing
    cat << 'EOF' > vmlinux.h
typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;

struct list_head {
    struct list_head *next, *prev;
};

struct task_struct {
    struct list_head tasks;
    int tgid;
    struct task_struct *real_parent;
};

struct sockaddr {
    unsigned short sa_family;
    char sa_data[14];
};

struct in_addr {
    __u32 s_addr;
};

struct sockaddr_in {
    short sin_family;
    __u16 sin_port;
    struct in_addr sin_addr;
    unsigned char sin_zero[8];
};

struct trace_event_raw_sys_enter {
    unsigned long long unused;
    long int id;
    unsigned long args[6];
};
EOF
    echo "[+] Fallback vmlinux.h created."
fi

# 3. Clean any old builds
rm -f guardian_bpfel.go guardian_bpfel.o kernel-guardian

# 4. Generate Go/eBPF binding code
echo "[+] Running go generate (compiling BPF program to bytecode)..."
go generate

# 5. Build the application
echo "[+] Compiling Go manager app..."
go build -o kernel-guardian main.go guardian_bpfel.go

# 6. Run the agent
echo "[+] Launching kernel-guardian HIDS..."
exec ./kernel-guardian
