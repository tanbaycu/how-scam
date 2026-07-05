/*
 * Author: tanbaycu
 * Project: kernel-guardian
 */

package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfEL -type event_t guardian guardian.bpf.c

const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorYellow = "\033[33m"
	colorCyan   = "\033[36m"
	colorBold   = "\033[1m"
)

type Config struct {
	SuspiciousBinaries []string `json:"suspicious_binaries"`
	SuspiciousPorts    []uint16 `json:"suspicious_ports"`
	WebProcesses       []string `json:"web_processes"`
	WhitelistedIPs     []string `json:"whitelisted_ips"`
}

var (
	config    Config
	procCache = make(map[uint32]string)
	cacheMu   sync.RWMutex
)

/*
 * Load cấu hình từ file rules.json
 */
func loadConfig() {
	file, err := os.ReadFile("rules.json")
	if err != nil {
		log.Println("[!] rules.json not found, using defaults")
		config = Config{
			SuspiciousBinaries: []string{"nc", "netcat", "socat", "nmap", "tcpdump", "ncat", "telnet"},
			SuspiciousPorts:    []uint16{4444, 9001, 1337, 6667},
			WebProcesses:       []string{"nginx", "apache", "httpd", "www-data", "node", "python", "php"},
			WhitelistedIPs:     []string{"127.0.0.1", "8.8.8.8"},
		}
		return
	}
	if err := json.Unmarshal(file, &config); err != nil {
		log.Fatalf("Failed to parse config: %v", err)
	}
}

func cacheProcess(pid uint32, comm string) {
	cacheMu.Lock()
	defer cacheMu.Unlock()
	procCache[pid] = comm
}

/*
 * Tìm tên tiến trình cha qua cache hoặc /proc
 */
func getParentComm(ppid uint32) string {
	cacheMu.RLock()
	if name, ok := procCache[ppid]; ok {
		cacheMu.RUnlock()
		return name
	}
	cacheMu.RUnlock()

	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", ppid))
	if err == nil {
		return string(bytes.TrimSpace(data))
	}
	return "unknown"
}

func int8ToStr(b []byte) string {
	n := bytes.IndexByte(b, 0)
	if n < 0 {
		n = len(b)
	}
	return string(b[:n])
}

func uint32ToIP(n uint32) net.IP {
	var bytes [4]byte
	binary.LittleEndian.PutUint32(bytes[:], n)
	return net.IPv4(bytes[0], bytes[1], bytes[2], bytes[3])
}

func printAlert(severity string, msg string) {
	timeStr := time.Now().Format("15:04:05.000")
	var sevColored string
	switch severity {
	case "CRITICAL":
		sevColored = colorRed + colorBold + "[CRITICAL]" + colorReset
	case "WARNING":
		sevColored = colorYellow + colorBold + "[WARNING]" + colorReset
	case "INFO":
		sevColored = colorCyan + "[INFO]" + colorReset
	default:
		sevColored = "[" + severity + "]"
	}
	fmt.Printf("%s %s %s\n", timeStr, sevColored, msg)
}

/*
 * Xử lý và phân tích các sự kiện nhận được từ Kernel
 */
func processEvent(event *guardianEventT) {
	comm := int8ToStr(event.Comm[:])
	filename := int8ToStr(event.Filename[:])

	if event.EventType == 1 {
		cacheProcess(event.Pid, comm)
	}

	parentComm := getParentComm(event.Ppid)

	if event.EventType == 1 { // EXECVE
		severity := "INFO"
		details := ""

		isShell := false
		shells := []string{
			"/bin/sh", "/bin/bash", "/bin/dash", "/bin/zsh",
			"/usr/bin/sh", "/usr/bin/bash", "/usr/bin/dash", "/usr/bin/zsh",
			"sh", "bash", "dash", "zsh",
		}
		for _, s := range shells {
			if filename == s || comm == s {
				isShell = true
				break
			}
		}

		isWebContext := false
		for _, w := range config.WebProcesses {
			if comm == w || parentComm == w {
				isWebContext = true
				break
			}
		}

		if isShell && isWebContext {
			severity = "CRITICAL"
			details = fmt.Sprintf("Shell spawned by web process '%s' (Possible RCE!)", parentComm)
		} else if isShell {
			if event.Uid == 0 {
				severity = "WARNING"
				details = "Shell executed with ROOT privileges"
			} else {
				severity = "INFO"
				details = "Interactive shell initiated"
			}
		}

		for _, tool := range config.SuspiciousBinaries {
			if comm == tool || bytes.Contains(event.Filename[:], []byte("/"+tool)) {
				severity = "WARNING"
				details = fmt.Sprintf("Suspicious utility '%s' executed", tool)
				break
			}
		}

		printAlert(severity, fmt.Sprintf("EXEC: [%s (PID:%d) -> %s (PID:%d)] executed '%s' (UID:%d) | %s",
			parentComm, event.Ppid, comm, event.Pid, filename, event.Uid, details))

	} else if event.EventType == 2 { // CONNECT
		ip := uint32ToIP(event.Daddr)
		port := event.Dport
		ipStr := ip.String()

		if ip.IsLoopback() {
			return
		}

		for _, wIp := range config.WhitelistedIPs {
			if ipStr == wIp {
				return
			}
		}

		severity := "INFO"
		details := ""

		suspicious := false
		for _, p := range config.SuspiciousPorts {
			if port == p {
				suspicious = true
				break
			}
		}

		if suspicious {
			severity = "CRITICAL"
			details = fmt.Sprintf("Outbound connection to flagged port %d (Potential Reverse Shell!)", port)
		} else if port == 22 || port == 23 {
			if event.Uid != 0 {
				severity = "WARNING"
				details = "Outbound remote admin connection"
			}
		}

		printAlert(severity, fmt.Sprintf("CONN: [%s (PID:%d) -> %s (PID:%d)] connected to %s:%d | %s",
			parentComm, event.Ppid, comm, event.Pid, ipStr, port, details))
	}
}

func main() {
	log.Println("==========================================================")
	log.Println("   kernel-guardian starting...                            ")
	log.Println("   Author: tanbaycu                                       ")
	log.Println("==========================================================")

	loadConfig()

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove memlock limits: %v", err)
	}

	var objs guardianObjects
	if err := loadGuardianObjects(&objs, nil); err != nil {
		log.Fatalf("Failed to load eBPF maps and programs: %v", err)
	}
	defer objs.Close()

	execLink, err := link.Tracepoint("syscalls", "sys_enter_execve", objs.TraceExecve, nil)
	if err != nil {
		log.Fatalf("Failed to attach execve tracepoint: %v", err)
	}
	defer execLink.Close()

	connectLink, err := link.Tracepoint("syscalls", "sys_enter_connect", objs.TraceConnect, nil)
	if err != nil {
		log.Fatalf("Failed to attach connect tracepoint: %v", err)
	}
	defer connectLink.Close()

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("Failed to initialize BPF Ring Buffer reader: %v", err)
	}
	defer rd.Close()

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-stopper
		log.Println("[!] Interrupted, stopping trace daemon...")
		rd.Close()
	}()

	log.Println("[*] Agent running. Monitoring system events...")

	var event guardianEventT
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			log.Printf("[!] Error reading from ring buffer: %v", err)
			continue
		}

		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
			log.Printf("[!] Error parsing event: %v", err)
			continue
		}

		processEvent(&event)
	}
}
