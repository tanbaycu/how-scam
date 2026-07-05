package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
)

func spawnBrowser(targetURL string, outDir string) (PageInfo, error) {
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.NoSandbox,
		chromedp.Flag("disable-setuid-sandbox", true),
		chromedp.Flag("disable-dev-shm-usage", true),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("ignore-certificate-errors", true),
	)

	allocCtx, cancel := chromedp.NewExecAllocator(context.Background(), opts...)
	defer cancel()

	ctx, cancel := chromedp.NewContext(allocCtx)
	defer cancel()

	ctx, cancel = context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	var netRequests []ExfilEndpoint
	var mu sync.Mutex

	chromedp.ListenTarget(ctx, func(ev interface{}) {
		if req, ok := ev.(*network.EventRequestWillBeSent); ok {
			if req.Request.Method == "POST" || strings.Contains(req.Request.URL, "api") {
				mu.Lock()
				netRequests = append(netRequests, ExfilEndpoint{
					URL:    req.Request.URL,
					Method: req.Request.Method,
					Type:   "network_intercept",
				})
				mu.Unlock()
			}
		}
	})

	var htmlContent string
	var title string
	var forms []FormInfo
	var screenshotBuf []byte

	err := chromedp.Run(ctx,
		network.Enable(),
		chromedp.Navigate(targetURL),
		chromedp.Sleep(3*time.Second),
		chromedp.Title(&title),
		chromedp.OuterHTML("html", &htmlContent),
		chromedp.Evaluate(`
			Array.from(document.querySelectorAll('form')).map(f => {
				return {
					action: f.action,
					fields: Array.from(f.querySelectorAll('input,select,textarea')).map(i => i.name || i.id || i.type || i.placeholder || '')
				};
			})
		`, &forms),
		chromedp.FullScreenshot(&screenshotBuf, 90),
	)
	if err != nil {
		return PageInfo{}, err
	}

	pageInfo := analyzePage(htmlContent, forms)
	pageInfo.Title = title
	pageInfo.URL = targetURL

	mu.Lock()
	pageInfo.ExfilEndpoints = append(pageInfo.ExfilEndpoints, netRequests...)
	mu.Unlock()

	typos := detectTyposquat(targetURL)
	if len(typos) > 0 {
		pageInfo.TyposquatHits = typos
		for _, t := range typos {
			pageInfo.Threats = append(pageInfo.Threats,
				fmt.Sprintf("Typosquatting: domain mimics '%s' (%.0f%% similar, technique: %s)", t.TargetBrand, t.Similarity*100, t.Technique))
			pageInfo.RiskScore += 25
		}
	}

	sslInfo, err := inspectSSL(targetURL)
	if err == nil {
		pageInfo.SSLAnalysis = &sslInfo
		sslScore, sslThreats := scoreSSL(sslInfo)
		pageInfo.RiskScore += sslScore
		pageInfo.Threats = append(pageInfo.Threats, sslThreats...)
	}

	if pageInfo.RiskScore > 100 {
		pageInfo.RiskScore = 100
	}

	if len(screenshotBuf) > 0 {
		_ = os.WriteFile(outDir+"/screenshot.png", screenshotBuf, 0644)
	}

	_ = os.WriteFile(outDir+"/page_source.html", []byte(htmlContent), 0644)

	return pageInfo, nil
}

func printBanner() {
	fmt.Print("\033[36m")
	fmt.Println(`
   ___  ___ __ _ _ __ ___        __ _ _   _  __ _ _ __ ___| (_) __ _ _ __
  / __|/ __/ _' | '_ ' _ \ ___ / _' | | | |/ _' | '__/ __| | |/ _' | '_ \
  \__ \ (_| (_| | | | | | |___| (_| | |_| | (_| | | | (__| | | (_| | | | |
  |___/\___\__,_|_| |_| |_|    \__, |\__,_|\__,_|_|  \___|_|_|\__,_|_| |_|
                                |___/`)
	fmt.Print("\033[0m")
	fmt.Println("\n  Anti-Phishing Threat Sandbox & Automated Takedown Engine")
	fmt.Println()
}

func scanSingle(targetURL string) {
	outDir := "output"
	_ = os.MkdirAll(outDir, 0755)

	fmt.Printf("[+] Target: %s\n", targetURL)
	fmt.Println("[+] Spawning isolated browser sandbox...")

	pageInfo, err := spawnBrowser(targetURL, outDir)
	if err != nil {
		log.Fatalf("[-] Sandbox failed: %v", err)
	}

	fmt.Printf("[+] Page title: %s\n", pageInfo.Title)

	if len(pageInfo.ExfilEndpoints) > 0 {
		fmt.Printf("[+] Intercepted %d suspicious network endpoint(s):\n", len(pageInfo.ExfilEndpoints))
		for _, ep := range pageInfo.ExfilEndpoints {
			fmt.Printf("    → [%s] %s (%s)\n", ep.Method, ep.URL, ep.Type)
		}
	}

	fmt.Println("[+] WHOIS lookup...")
	domainInfo, err := getDomainInfo(targetURL)
	if err != nil {
		fmt.Printf("[!] WHOIS failed: %v\n", err)
	} else {
		fmt.Printf("    Registrar:  %s\n", domainInfo.Registrar)
		fmt.Printf("    Abuse:      %s\n", domainInfo.AbuseEmail)
		fmt.Printf("    Registered: %s\n", domainInfo.CreationDate)
	}

	if pageInfo.SSLAnalysis != nil {
		fmt.Printf("[+] SSL: issuer=%s, age=%d days, self-signed=%v\n",
			pageInfo.SSLAnalysis.Issuer, pageInfo.SSLAnalysis.DaysOld, pageInfo.SSLAnalysis.SelfSigned)
	}

	if len(pageInfo.TyposquatHits) > 0 {
		fmt.Println("[+] Typosquatting detected:")
		for _, t := range pageInfo.TyposquatHits {
			fmt.Printf("    → mimics '%s' (%.0f%% match, %s)\n", t.TargetBrand, t.Similarity*100, t.Technique)
		}
	}

	fmt.Println()
	verdict := "CLEAN"
	if pageInfo.RiskScore >= 70 {
		verdict = "CONFIRMED_PHISHING"
		fmt.Printf("\033[31;1m[██ VERDICT: %s | Score: %d/100 ██]\033[0m\n", verdict, pageInfo.RiskScore)
	} else if pageInfo.RiskScore >= 40 {
		verdict = "SUSPICIOUS"
		fmt.Printf("\033[33;1m[▓▓ VERDICT: %s | Score: %d/100 ▓▓]\033[0m\n", verdict, pageInfo.RiskScore)
	} else {
		fmt.Printf("\033[32m[░░ VERDICT: %s | Score: %d/100 ░░]\033[0m\n", verdict, pageInfo.RiskScore)
	}

	for _, t := range pageInfo.Threats {
		fmt.Printf("  • %s\n", t)
	}
	fmt.Println()

	report := buildFullReport(targetURL, pageInfo, domainInfo)
	if err := exportJSON(report, outDir+"/report.json"); err == nil {
		fmt.Println("[+] Full JSON report → output/report.json")
	}

	if pageInfo.RiskScore >= 40 {
		abuseText := generateAbuseReport(targetURL, domainInfo, pageInfo)
		if err := os.WriteFile(outDir+"/abuse_report.txt", []byte(abuseText), 0644); err == nil {
			fmt.Println("[+] Abuse takedown draft → output/abuse_report.txt")
		}
	}

	fmt.Println("[+] Screenshot → output/screenshot.png")
	fmt.Println("[+] Page source → output/page_source.html")
}

func scanBatch(filePath string) {
	file, err := os.Open(filePath)
	if err != nil {
		log.Fatalf("[-] Cannot open URL list: %v", err)
	}
	defer file.Close()

	var urls []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			urls = append(urls, line)
		}
	}

	fmt.Printf("[+] Loaded %d target(s) from %s\n\n", len(urls), filePath)

	var results []FullReport

	for i, u := range urls {
		fmt.Printf("\033[36m━━━ [%d/%d] %s ━━━\033[0m\n", i+1, len(urls), u)

		outDir := fmt.Sprintf("output/scan_%d", i+1)
		_ = os.MkdirAll(outDir, 0755)

		pageInfo, err := spawnBrowser(u, outDir)
		if err != nil {
			fmt.Printf("[-] Failed: %v\n\n", err)
			continue
		}

		domainInfo, _ := getDomainInfo(u)
		report := buildFullReport(u, pageInfo, domainInfo)
		results = append(results, report)

		_ = exportJSON(report, outDir+"/report.json")

		if pageInfo.RiskScore >= 40 {
			abuseText := generateAbuseReport(u, domainInfo, pageInfo)
			_ = os.WriteFile(outDir+"/abuse_report.txt", []byte(abuseText), 0644)
		}

		fmt.Printf("  Verdict: %s | Score: %d/100\n\n", report.Verdict, pageInfo.RiskScore)
	}

	batchData, _ := json.MarshalIndent(results, "", "  ")
	_ = os.WriteFile("output/batch_results.json", batchData, 0644)
	fmt.Printf("[+] Batch summary → output/batch_results.json (%d scanned)\n", len(results))
}

func main() {
	if len(os.Args) < 2 {
		printBanner()
		fmt.Println("Usage:")
		fmt.Println("  scam-guardian <url>              Scan a single URL")
		fmt.Println("  scam-guardian --batch <file>     Scan URLs from a file (one per line)")
		fmt.Println("  scam-guardian --serve :8080      Start HTTP API server")
		os.Exit(0)
	}

	printBanner()

	switch os.Args[1] {
	case "--batch":
		if len(os.Args) < 3 {
			log.Fatal("[-] Provide a file path: scam-guardian --batch urls.txt")
		}
		scanBatch(os.Args[2])

	case "--serve":
		addr := ":8080"
		if len(os.Args) >= 3 {
			addr = os.Args[2]
		}
		fmt.Printf("[+] API server listening on %s\n", addr)
		http.HandleFunc("/scan", apiScanHandler)
		log.Fatal(http.ListenAndServe(addr, nil))

	default:
		scanSingle(os.Args[1])
	}
}

func apiScanHandler(w http.ResponseWriter, r *http.Request) {
	targetURL := r.URL.Query().Get("url")
	if targetURL == "" {
		http.Error(w, `{"error":"missing ?url= parameter"}`, http.StatusBadRequest)
		return
	}

	outDir := "output/api_scan"
	_ = os.MkdirAll(outDir, 0755)

	pageInfo, err := spawnBrowser(targetURL, outDir)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusInternalServerError)
		return
	}

	domainInfo, _ := getDomainInfo(targetURL)
	report := buildFullReport(targetURL, pageInfo, domainInfo)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(report)
}
