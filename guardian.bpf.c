/*
 * Author: tanbaycu
 * Project: kernel-guardian
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

#define EVENT_TYPE_EXEC 1
#define EVENT_TYPE_CONNECT 2

#ifndef AF_INET
#define AF_INET 2
#endif

#define bpf_ntohs(x) __builtin_bswap16(x)

struct event_t {
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u32 event_type;
    char comm[16];
    char filename[128];
    __u32 daddr;
    __u16 dport;
    __u8 is_ipv4;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 18);
} events SEC(".maps");

/* 
 * Hook vào syscall execve để theo dõi các tiến trình được sinh ra
 */
SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e;
    
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;
    
    e->event_type = EVENT_TYPE_EXEC;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->uid = bpf_get_current_uid_gid();
    
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    
    // Đọc thông tin PPID từ task_struct của kernel
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *real_parent = BPF_CORE_READ(task, real_parent);
    e->ppid = BPF_CORE_READ(real_parent, tgid);
    
    const char *filename_ptr = (const char *)BPF_CORE_READ(ctx, args[0]);
    bpf_probe_read_user_str(&e->filename, sizeof(e->filename), filename_ptr);
    
    e->daddr = 0;
    e->dport = 0;
    e->is_ipv4 = 0;
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/*
 * Hook vào syscall connect để theo dõi kết nối mạng outbound
 */
SEC("tracepoint/syscalls/sys_enter_connect")
int trace_connect(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e;
    
    struct sockaddr *addr_ptr = (struct sockaddr *)BPF_CORE_READ(ctx, args[1]);
    if (!addr_ptr) return 0;
    
    short family = 0;
    bpf_probe_read_user(&family, sizeof(family), &addr_ptr->sa_family);
    if (family != AF_INET) return 0;
    
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;
    
    e->event_type = EVENT_TYPE_CONNECT;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->uid = bpf_get_current_uid_gid();
    
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *real_parent = BPF_CORE_READ(task, real_parent);
    e->ppid = BPF_CORE_READ(real_parent, tgid);
    
    struct sockaddr_in addr;
    bpf_probe_read_user(&addr, sizeof(addr), addr_ptr);
    
    e->daddr = addr.sin_addr.s_addr;
    e->dport = bpf_ntohs(addr.sin_port);
    e->is_ipv4 = 1;
    e->filename[0] = '\0';
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}
