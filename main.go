package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/chromedp/chromedp"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: ./scam-guardian <scam-url>")
		os.Exit(1)
	}
	targetURL := os.Args[1]

	fmt.Println("\033[36m==========================================================\033[0m")
	fmt.Println("\033[36m   scam-guardian: Threat Sandbox Initiated                \033[0m")
	fmt.Println("\033[36m==========================================================\033[0m")

	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.NoSandbox,
		chromedp.Flag("disable-setuid-sandbox", true),
		chromedp.Flag("disable-dev-shm-usage", true),
		chromedp.Flag("disable-gpu", true),
	)

	allocCtx, cancel := chromedp.NewExecAllocator(context.Background(), opts...)
	defer cancel()

	ctx, cancel := chromedp.NewContext(allocCtx)
	defer cancel()

	ctx, cancel = context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	var htmlContent string
	var title string
	var forms []FormInfo
	var screenshotBuf []byte

	fmt.Println("[+] Spawning Headless Sandbox...")
	err := chromedp.Run(ctx,
		chromedp.Navigate(targetURL),
		chromedp.Sleep(2*time.Second),
		chromedp.Title(&title),
		chromedp.OuterHTML("html", &htmlContent),
		chromedp.Evaluate(`
			Array.from(document.querySelectorAll('form')).map(f => {
				return {
					action: f.action,
					fields: Array.from(f.querySelectorAll('input')).map(i => i.name || i.id || i.type)
				};
			})
		`, &forms),
		chromedp.FullScreenshot(&screenshotBuf, 90),
	)

	if err != nil {
		log.Fatalf("[-] Sandbox execution failed: %v", err)
	}

	fmt.Printf("[+] Analyzing Site Title: %s\n", title)
	pageInfo := analyzePage(htmlContent, forms)
	pageInfo.Title = title
	pageInfo.URL = targetURL

	outDir := "output"
	_ = os.MkdirAll(outDir, 0755)

	screenshotPath := outDir + "/screenshot.png"
	if err := os.WriteFile(screenshotPath, screenshotBuf, 0644); err == nil {
		fmt.Printf("[+] Screenshot stored successfully at %s\n", screenshotPath)
	}

	fmt.Println("[+] Fetching DNS and WHOIS Registry records...")
	domainInfo, err := getDomainInfo(targetURL)
	if err != nil {
		fmt.Printf("[!] WHOIS Lookup failed: %v\n", err)
	} else {
		fmt.Printf("[+] Registrar: %s\n", domainInfo.Registrar)
		fmt.Printf("[+] Abuse Contact: %s\n", domainInfo.AbuseEmail)
	}

	fmt.Println("\n\033[33m=================== FORENSIC ASSESSMENT ===================\033[0m")
	if pageInfo.RiskScore >= 70 {
		fmt.Printf("\033[31m[CRITICAL] Security Alert! Risk Score: %d/100\033[0m\n", pageInfo.RiskScore)
	} else if pageInfo.RiskScore >= 40 {
		fmt.Printf("\033[33m[WARNING] Suspicious Activity. Risk Score: %d/100\033[0m\n", pageInfo.RiskScore)
	} else {
		fmt.Printf("\033[32m[INFO] Low Risk. Risk Score: %d/100\033[0m\n", pageInfo.RiskScore)
	}

	for _, threat := range pageInfo.Threats {
		fmt.Printf(" - %s\n", threat)
	}

	if pageInfo.RiskScore >= 40 {
		fmt.Println("\n\033[31m=================== ABUSE REPORT COMPILED ===================\033[0m")
		report := generateAbuseReport(targetURL, domainInfo, pageInfo)
		fmt.Println(report)
		
		reportPath := outDir + "/abuse_report.txt"
		if err := os.WriteFile(reportPath, []byte(report), 0644); err == nil {
			fmt.Printf("\033[32m[+] Takedown report saved at %s\033[0m\n", reportPath)
		}
	}
}
