package main

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/likexian/whois"
	whoisparser "github.com/likexian/whois-parser"
)

type DomainInfo struct {
	Domain       string   `json:"domain"`
	Registrar    string   `json:"registrar"`
	AbuseEmail   string   `json:"abuse_email"`
	NameServers  []string `json:"name_servers"`
	CreationDate string   `json:"creation_date"`
	ExpiryDate   string   `json:"expiry_date"`
	Country      string   `json:"country"`
}

type FullReport struct {
	Timestamp  string     `json:"timestamp"`
	Target     string     `json:"target_url"`
	Page       PageInfo   `json:"page_analysis"`
	Domain     DomainInfo `json:"domain_intel"`
	Verdict    string     `json:"verdict"`
	AbuseEmail string     `json:"abuse_contact"`
	ReportBody string     `json:"abuse_report_body"`
}

func getDomainInfo(targetURL string) (DomainInfo, error) {
	u, err := url.Parse(targetURL)
	if err != nil {
		return DomainInfo{}, err
	}
	host := u.Hostname()
	parts := strings.Split(host, ".")
	if len(parts) > 2 {
		host = strings.Join(parts[len(parts)-2:], ".")
	}

	result, err := whois.Whois(host)
	if err != nil {
		return DomainInfo{}, err
	}

	parsed, err := whoisparser.Parse(result)
	if err != nil {
		return DomainInfo{}, err
	}

	info := DomainInfo{
		Domain:       host,
		Registrar:    parsed.Registrar.Name,
		AbuseEmail:   parsed.Registrar.AbuseEmail,
		NameServers:  parsed.Domain.NameServers,
		CreationDate: parsed.Domain.CreatedDate,
		ExpiryDate:   parsed.Domain.ExpirationDate,
	}

	if parsed.Registrant != nil {
		info.Country = parsed.Registrant.Country
	}

	if info.AbuseEmail == "" && parsed.Registrar.Email != "" {
		info.AbuseEmail = parsed.Registrar.Email
	}

	return info, nil
}

func generateAbuseReport(targetURL string, info DomainInfo, pageInfo PageInfo) string {
	threatsJoined := strings.Join(pageInfo.Threats, "\n  - ")

	var exfilSection string
	if len(pageInfo.ExfilEndpoints) > 0 {
		var lines []string
		for _, ep := range pageInfo.ExfilEndpoints {
			lines = append(lines, fmt.Sprintf("  - [%s] %s (%s)", ep.Method, ep.URL, ep.Type))
		}
		exfilSection = "\n[Data Exfiltration Endpoints]\n" + strings.Join(lines, "\n")
	}

	return fmt.Sprintf(`Subject: URGENT: Active Phishing Site Takedown Request — %s

Dear Security/Abuse Team,

An active phishing operation has been identified on infrastructure registered
through your organization. The site is collecting user credentials and
financial data from victims in real-time.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[Target Information]
  Domain:       %s
  Phishing URL: %s
  Registrar:    %s
  Name Servers: %s
  Registered:   %s

[Threat Assessment]
  Risk Score: %d/100
  Indicators:
  - %s
%s

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Immediate suspension of the domain and associated hosting account is
requested under your Acceptable Use Policy to prevent further harm.

Evidence package (screenshot + structured JSON report) is attached or
available upon request.

Regards,
Automated Threat Response — scam-guardian
Timestamp: %s
`, info.Domain, info.Domain, targetURL, info.Registrar,
		strings.Join(info.NameServers, ", "), info.CreationDate,
		pageInfo.RiskScore, threatsJoined, exfilSection,
		time.Now().UTC().Format(time.RFC3339))
}

func buildFullReport(targetURL string, pageInfo PageInfo, domainInfo DomainInfo) FullReport {
	verdict := "CLEAN"
	if pageInfo.RiskScore >= 70 {
		verdict = "CONFIRMED_PHISHING"
	} else if pageInfo.RiskScore >= 40 {
		verdict = "SUSPICIOUS"
	}

	report := FullReport{
		Timestamp:  time.Now().UTC().Format(time.RFC3339),
		Target:     targetURL,
		Page:       pageInfo,
		Domain:     domainInfo,
		Verdict:    verdict,
		AbuseEmail: domainInfo.AbuseEmail,
	}

	if pageInfo.RiskScore >= 40 {
		report.ReportBody = generateAbuseReport(targetURL, domainInfo, pageInfo)
	}

	return report
}

func exportJSON(report FullReport, path string) error {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}
