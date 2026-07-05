package main

import (
	"strings"
)

type FormInfo struct {
	Action string   `json:"action"`
	Fields []string `json:"fields"`
}

type ExfilEndpoint struct {
	URL    string `json:"url"`
	Method string `json:"method"`
	Type   string `json:"type"`
}

type PageInfo struct {
	URL             string          `json:"url"`
	Title           string          `json:"title"`
	Forms           []FormInfo      `json:"forms"`
	ExfilEndpoints  []ExfilEndpoint `json:"exfil_endpoints"`
	HasPassword     bool            `json:"has_password"`
	HasOTP          bool            `json:"has_otp"`
	HasCard         bool            `json:"has_card"`
	RiskScore       int             `json:"risk_score"`
	Threats         []string        `json:"threats"`
	TyposquatHits   []TyposquatResult `json:"typosquat_hits,omitempty"`
	SSLAnalysis     *SSLInfo        `json:"ssl_analysis,omitempty"`
}

var sensitiveInputPatterns = map[string]string{
	"pass":          "password",
	"pwd":           "password",
	"otp":           "otp",
	"verification":  "otp",
	"token":         "otp",
	"mfa":           "otp",
	"2fa":           "otp",
	"card":          "card",
	"cvv":           "card",
	"cvc":           "card",
	"ccnum":         "card",
	"cardnumber":    "card",
	"expiry":        "card",
	"expire":        "card",
	"ssn":           "pii",
	"social":        "pii",
	"national":      "pii",
	"cmnd":          "pii",
	"cccd":          "pii",
}

func classifyInput(fieldName string) string {
	lower := strings.ToLower(fieldName)
	for pattern, category := range sensitiveInputPatterns {
		if strings.Contains(lower, pattern) {
			return category
		}
	}
	return ""
}

func analyzePage(html string, forms []FormInfo) PageInfo {
	info := PageInfo{Forms: forms}
	htmlLower := strings.ToLower(html)

	piiDetected := false

	for _, f := range forms {
		for _, field := range f.Fields {
			cat := classifyInput(field)
			switch cat {
			case "password":
				info.HasPassword = true
			case "otp":
				info.HasOTP = true
			case "card":
				info.HasCard = true
			case "pii":
				piiDetected = true
			}
		}

		if f.Action != "" && !strings.HasPrefix(f.Action, "javascript:") {
			info.ExfilEndpoints = append(info.ExfilEndpoints, ExfilEndpoint{
				URL:    f.Action,
				Method: "POST",
				Type:   "form_action",
			})
		}
	}

	if info.HasPassword {
		info.Threats = append(info.Threats, "Credential harvesting form detected")
		info.RiskScore += 40
	}
	if info.HasOTP {
		info.Threats = append(info.Threats, "OTP/MFA bypass input detected")
		info.RiskScore += 30
	}
	if info.HasCard {
		info.Threats = append(info.Threats, "Financial data collection (credit card) detected")
		info.RiskScore += 30
	}
	if piiDetected {
		info.Threats = append(info.Threats, "Personal identity information (PII/CCCD/SSN) field detected")
		info.RiskScore += 25
	}

	evasionPatterns := map[string]string{
		"preventdefault":       "Event hijacking (preventDefault)",
		"contextmenu":         "Right-click disabled",
		"devtools":            "DevTools detection script",
		"debugger":            "Anti-debugging trap",
		"disable-devtool":     "DevTools blocking library",
		"console.log=":        "Console output suppression",
		"window.location.replace": "Forced redirect chain",
	}

	evasionCount := 0
	for pattern, desc := range evasionPatterns {
		if strings.Contains(htmlLower, pattern) {
			info.Threats = append(info.Threats, "Evasion: "+desc)
			evasionCount++
		}
	}
	if evasionCount > 0 {
		info.RiskScore += evasionCount * 5
	}

	brandTargets := map[string]string{
		"paypal":       "PayPal",
		"metamask":     "MetaMask",
		"binance":      "Binance",
		"coinbase":     "Coinbase",
		"facebook":     "Facebook",
		"google":       "Google",
		"microsoft":    "Microsoft",
		"outlook":      "Outlook",
		"netflix":      "Netflix",
		"apple":        "Apple",
		"amazon":       "Amazon",
		"instagram":    "Instagram",
		"vietcombank":  "Vietcombank",
		"mbbank":       "MB Bank",
		"techcombank":  "Techcombank",
		"tpbank":       "TPBank",
		"momo":         "MoMo",
		"zalopay":      "ZaloPay",
		"vnpay":        "VNPay",
	}

	for keyword, brand := range brandTargets {
		if strings.Contains(htmlLower, keyword) {
			info.Threats = append(info.Threats, "Impersonating brand: "+brand)
			info.RiskScore += 20
			break
		}
	}

	if info.RiskScore > 100 {
		info.RiskScore = 100
	}

	return info
}
