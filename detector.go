package main

import (
	"strings"
)

type FormInfo struct {
	Action string   `json:"action"`
	Fields []string `json:"fields"`
}

type PageInfo struct {
	URL         string     `json:"url"`
	Title       string     `json:"title"`
	Forms       []FormInfo `json:"forms"`
	HasPassword bool       `json:"has_password"`
	HasOTP      bool       `json:"has_otp"`
	HasCard     bool       `json:"has_card"`
	RiskScore   int        `json:"risk_score"`
	Threats     []string   `json:"threats"`
}

func analyzePage(html string, forms []FormInfo) PageInfo {
	info := PageInfo{
		Forms: forms,
	}

	htmlLower := strings.ToLower(html)

	for _, f := range forms {
		for _, field := range f.Fields {
			fieldLower := strings.ToLower(field)
			if strings.Contains(fieldLower, "pass") {
				info.HasPassword = true
			}
			if strings.Contains(fieldLower, "otp") || strings.Contains(fieldLower, "verification") || strings.Contains(fieldLower, "token") {
				info.HasOTP = true
			}
			if strings.Contains(fieldLower, "card") || strings.Contains(fieldLower, "cvv") || strings.Contains(fieldLower, "ccnum") {
				info.HasCard = true
			}
		}
	}

	if info.HasPassword {
		info.Threats = append(info.Threats, "Credential collection form detected")
		info.RiskScore += 40
	}
	if info.HasOTP {
		info.Threats = append(info.Threats, "OTP/2FA token extraction input detected")
		info.RiskScore += 30
	}
	if info.HasCard {
		info.Threats = append(info.Threats, "Credit card detail harvesting input detected")
		info.RiskScore += 30
	}

	bypassKeywords := []string{
		"preventdefault",
		"contextmenu",
		"keydown",
		"devtools",
		"debugger",
	}

	for _, kw := range bypassKeywords {
		if strings.Contains(htmlLower, kw) {
			info.Threats = append(info.Threats, "Anti-debugging/Right-click prevention script pattern matched: "+kw)
			info.RiskScore += 10
			break
		}
	}

	brandKeywords := []string{
		"paypal", "metamask", "binance", "coinbase", "facebook", "google",
		"microsoft", "outlook", "netflix", "apple", "vietcombank", "mbbank",
	}

	for _, brand := range brandKeywords {
		if strings.Contains(htmlLower, brand) {
			info.Threats = append(info.Threats, "References targeted brand: "+brand)
			info.RiskScore += 20
			break
		}
	}

	return info
}
