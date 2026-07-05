package main

import (
	"crypto/tls"
	"fmt"
	"math"
	"net"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"
)

type SSLInfo struct {
	Issuer     string `json:"issuer"`
	Subject    string `json:"subject"`
	NotBefore  string `json:"not_before"`
	NotAfter   string `json:"not_after"`
	DaysOld    int    `json:"days_old"`
	SelfSigned bool   `json:"self_signed"`
	Valid      bool   `json:"valid"`
}

type TyposquatResult struct {
	TargetBrand string  `json:"target_brand"`
	Similarity  float64 `json:"similarity"`
	Technique   string  `json:"technique"`
}

func inspectSSL(targetURL string) (SSLInfo, error) {
	u, err := url.Parse(targetURL)
	if err != nil {
		return SSLInfo{}, err
	}
	if u.Scheme != "https" {
		return SSLInfo{Valid: false}, nil
	}

	host := u.Hostname()
	port := u.Port()
	if port == "" {
		port = "443"
	}

	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 5 * time.Second},
		"tcp",
		host+":"+port,
		&tls.Config{InsecureSkipVerify: true},
	)
	if err != nil {
		return SSLInfo{}, err
	}
	defer conn.Close()

	cert := conn.ConnectionState().PeerCertificates[0]

	info := SSLInfo{
		Issuer:    cert.Issuer.CommonName,
		Subject:   cert.Subject.CommonName,
		NotBefore: cert.NotBefore.Format("2006-01-02"),
		NotAfter:  cert.NotAfter.Format("2006-01-02"),
		DaysOld:   int(time.Since(cert.NotBefore).Hours() / 24),
		Valid:     time.Now().Before(cert.NotAfter) && time.Now().After(cert.NotBefore),
	}

	if cert.Issuer.CommonName == cert.Subject.CommonName {
		info.SelfSigned = true
	}

	return info, nil
}

func levenshtein(a, b string) int {
	la := utf8.RuneCountInString(a)
	lb := utf8.RuneCountInString(b)
	ra := []rune(a)
	rb := []rune(b)

	d := make([][]int, la+1)
	for i := range d {
		d[i] = make([]int, lb+1)
		d[i][0] = i
	}
	for j := 0; j <= lb; j++ {
		d[0][j] = j
	}

	for i := 1; i <= la; i++ {
		for j := 1; j <= lb; j++ {
			cost := 1
			if ra[i-1] == rb[j-1] {
				cost = 0
			}
			d[i][j] = min(d[i-1][j]+1, min(d[i][j-1]+1, d[i-1][j-1]+cost))
		}
	}
	return d[la][lb]
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

var typosquatTargets = []string{
	"paypal", "facebook", "google", "microsoft", "apple",
	"amazon", "netflix", "instagram", "tiktok", "twitter",
	"binance", "coinbase", "metamask", "blockchain",
	"vietcombank", "mbbank", "techcombank", "tpbank", "bidv",
	"agribank", "sacombank", "vpbank", "acb",
	"momo", "zalopay", "vnpay", "viettelpay",
}

var homoglyphs = map[rune]rune{
	'0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's',
	'7': 't', '8': 'b', '@': 'a',
}

func normalizeHomoglyphs(s string) string {
	var b strings.Builder
	for _, r := range s {
		if replacement, ok := homoglyphs[r]; ok {
			b.WriteRune(replacement)
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func detectTyposquat(targetURL string) []TyposquatResult {
	u, err := url.Parse(targetURL)
	if err != nil {
		return nil
	}

	host := strings.ToLower(u.Hostname())
	parts := strings.Split(host, ".")
	if len(parts) < 2 {
		return nil
	}
	domainBase := parts[len(parts)-2]
	normalized := normalizeHomoglyphs(domainBase)

	var results []TyposquatResult

	for _, brand := range typosquatTargets {
		dist := levenshtein(normalized, brand)
		maxLen := math.Max(float64(len(normalized)), float64(len(brand)))
		if maxLen == 0 {
			continue
		}
		similarity := 1.0 - float64(dist)/maxLen

		if similarity >= 0.65 && normalized != brand {
			technique := "character substitution"
			if strings.Contains(normalized, brand) || strings.Contains(brand, normalized) {
				technique = "prefix/suffix injection"
			}
			if normalized != domainBase {
				technique = "homoglyph attack"
			}

			results = append(results, TyposquatResult{
				TargetBrand: brand,
				Similarity:  math.Round(similarity*100) / 100,
				Technique:   technique,
			})
		}

		if normalized == brand && domainBase != brand {
			results = append(results, TyposquatResult{
				TargetBrand: brand,
				Similarity:  1.0,
				Technique:   "homoglyph attack (exact match after normalization)",
			})
		}
	}

	return results
}

func scoreSSL(info SSLInfo) (int, []string) {
	score := 0
	var threats []string

	if info.SelfSigned {
		score += 25
		threats = append(threats, "Self-signed SSL certificate")
	}

	if info.DaysOld < 7 {
		score += 20
		threats = append(threats, fmt.Sprintf("Certificate issued %d day(s) ago — brand new domain", info.DaysOld))
	} else if info.DaysOld < 30 {
		score += 10
		threats = append(threats, fmt.Sprintf("Certificate issued %d day(s) ago — recently registered", info.DaysOld))
	}

	if !info.Valid {
		score += 15
		threats = append(threats, "SSL certificate expired or not yet valid")
	}

	freeIssuers := []string{"let's encrypt", "zerossl", "buypass", "ssl.com"}
	issuerLower := strings.ToLower(info.Issuer)
	for _, free := range freeIssuers {
		if strings.Contains(issuerLower, free) {
			score += 5
			threats = append(threats, fmt.Sprintf("Free SSL issuer: %s (commonly abused by phishing)", info.Issuer))
			break
		}
	}

	return score, threats
}
