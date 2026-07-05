package main

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/likexian/whois"
	whoisparser "github.com/likexian/whois-parser"
)

type DomainInfo struct {
	Domain     string
	Registrar  string
	AbuseEmail string
	NameServer []string
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
		Domain:     host,
		Registrar:  parsed.Registrar.Name,
		AbuseEmail: parsed.Registrar.AbuseEmail,
		NameServer: parsed.Domain.NameServers,
	}

	if info.AbuseEmail == "" && parsed.Registrar.Email != "" {
		info.AbuseEmail = parsed.Registrar.Email
	}

	return info, nil
}

func generateAbuseReport(targetURL string, info DomainInfo, pageInfo PageInfo) string {
	threatsJoined := strings.Join(pageInfo.Threats, "\n- ")

	return fmt.Sprintf(`Subject: URGENT: Phishing Host Takedown Request - %s

Dear Security/Abuse Team,

We have detected an active phishing/scam site hosted on your network/domain infrastructure. This site is harvesting credentials and sensitive information from unsuspecting users.

Domain: %s
Phishing URL: %s
Registrar: %s
Name Servers: %s

[Forensic Analysis & Indicators of Compromise]
Risk Score: %d/100
Detected Indicators:
- %s

Please suspend the offending account and disable access to this URL immediately to prevent further damage to users.

Best regards,
Automated Security Response Engine
scam-guardian
`, info.Domain, info.Domain, targetURL, info.Registrar, strings.Join(info.NameServer, ", "), pageInfo.RiskScore, threatsJoined)
}
