package domain

import (
	"bufio"
	"math"
	"os"
	"strings"
	"sync"
)

// Auditor performs domain reputation checks
type Auditor struct {
	mining  map[string]bool
	fraud   map[string]bool
	custom  map[string]string // domain -> tag
	mu      sync.RWMutex
}

// AuditResult holds the result of domain audit
type AuditResult struct {
	Match   bool
	Label   string
	Score   int
	Domain  string
	Details string
}

// suspiciousTLDs are commonly used by malicious domains
var suspiciousTLDs = map[string]bool{
	"xyz": true, "tk": true, "ml": true, "ga": true,
	"cf": true, "gq": true, "top": true, "club": true,
}

// New creates a new domain auditor
func New() *Auditor {
	return &Auditor{
		mining: make(map[string]bool),
		fraud:  make(map[string]bool),
		custom: make(map[string]string),
	}
}

// LoadMiningList loads mining domain list from file
func (a *Auditor) LoadMiningList(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	a.mu.Lock()
	defer a.mu.Unlock()
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			a.mining[strings.ToLower(line)] = true
		}
	}
	return scanner.Err()
}

// LoadFraudList loads fraud domain list from file
func (a *Auditor) LoadFraudList(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	a.mu.Lock()
	defer a.mu.Unlock()
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			a.fraud[strings.ToLower(line)] = true
		}
	}
	return scanner.Err()
}

// LoadCustomList loads custom domain list from file (format: domain,tag)
func (a *Auditor) LoadCustomList(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	a.mu.Lock()
	defer a.mu.Unlock()
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			parts := strings.Split(line, ",")
			if len(parts) >= 2 {
				domain := strings.ToLower(strings.TrimSpace(parts[0]))
				tag := strings.TrimSpace(parts[1])
				a.custom[domain] = tag
			}
		}
	}
	return scanner.Err()
}

// Audit checks a domain against all domain lists and performs heuristic analysis
func (a *Auditor) Audit(domain string) *AuditResult {
	if domain == "" {
		return &AuditResult{Match: false}
	}

	domain = strings.ToLower(strings.TrimSpace(domain))

	a.mu.RLock()
	defer a.mu.RUnlock()

	// Check mining list
	if a.mining[domain] {
		return &AuditResult{Match: true, Label: "mining", Score: 100, Domain: domain}
	}

	// Check fraud list
	if a.fraud[domain] {
		return &AuditResult{Match: true, Label: "fraud", Score: 90, Domain: domain}
	}

	// Check custom list
	if tag, ok := a.custom[domain]; ok {
		return &AuditResult{Match: true, Label: tag, Score: 70, Domain: domain}
	}

	// DGA detection (entropy > 4.0)
	if a.detectDGA(domain) {
		return &AuditResult{Match: true, Label: "dga", Score: 75, Domain: domain, Details: "High entropy domain"}
	}

	// DNS Tunnel detection (subdomain count > 5 and entropy > 3.5)
	if a.detectDNSTunnel(domain) {
		return &AuditResult{Match: true, Label: "dns_tunnel", Score: 80, Domain: domain, Details: "High subdomain count"}
	}

	// Suspicious TLD detection
	if a.detectSuspiciousTLD(domain) {
		return &AuditResult{Match: true, Label: "suspicious", Score: 40, Domain: domain, Details: "Suspicious TLD"}
	}

	return &AuditResult{Match: false, Domain: domain}
}

// detectDGA detects domain generation algorithm domains by entropy analysis
func (a *Auditor) detectDGA(domain string) bool {
	// Remove TLD
	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return false
	}
	baseDomain := parts[0]

	entropy := calculateEntropy(baseDomain)
	return entropy > 4.0
}

// detectDNSTunnel detects DNS tunnel by subdomain count and entropy
func (a *Auditor) detectDNSTunnel(domain string) bool {
	parts := strings.Split(domain, ".")
	// Count subdomains (everything before the main domain + TLD)
	if len(parts) < 3 {
		return false
	}
	subdomainCount := len(parts) - 2

	if subdomainCount > 5 {
		entropy := calculateEntropy(domain)
		if entropy > 3.5 {
			return true
		}
	}
	return false
}

// detectSuspiciousTLD checks for suspicious top-level domains
func (a *Auditor) detectSuspiciousTLD(domain string) bool {
	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return false
	}
	tld := parts[len(parts)-1]
	return suspiciousTLDs[tld]
}

// calculateEntropy computes Shannon entropy of a string
func calculateEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}

	freq := make(map[rune]int)
	for _, c := range s {
		freq[c]++
	}

	entropy := 0.0
	for _, count := range freq {
		f := float64(count) / float64(len(s))
		entropy -= f * math.Log2(f)
	}

	return entropy
}