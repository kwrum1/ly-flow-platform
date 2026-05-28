package ioc

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/sha3"
)

type Database struct {
	ips          map[string]*IOCEntry
	domains      map[string]*IOCEntry
	urls         map[string]*IOCEntry
	certThumbprints map[string]*IOCEntry
	ja3          map[string]*IOCEntry
	mu           sync.RWMutex
	totalLoaded  int
	lastUpdate   time.Time
}

type IOCType string

const (
	IOCTypeIP       IOCType = "ip"
	IOCTypeDomain   IOCType = "domain"
	IOCTypeURL      IOCType = "url"
	IOCTypeCert     IOCType = "certificate"
	IOCTypeJA3      IOCType = "ja3"
)

type IOCEntry struct {
	Type        IOCType
	Value       string
	Source      string
	Confidence  int
	ThreatType  string
	Description string
	FirstSeen   time.Time
	LastSeen    time.Time
	Tags        []string
	Raw         map[string]interface{}
}

type Feed struct {
	Name     string
	URL      string
	Interval time.Duration
	Format   string
}

var DefaultFeeds = []Feed{
	{"AlienVault OTX", "https://otx.alienvault.com/api/v1/pulses/subscribed", 1 * time.Hour, "json"},
	{"Emerging Threats", "https://rules.emergingthreats.net/blockrules/compromised-ips.txt", 6 * time.Hour, "plain"},
	{"URLhaus", "https://urlhaus.abuse.ch/downloads/json/", 1 * time.Hour, "json"},
}

func NewDatabase() *Database {
	db := &Database{
		ips:          make(map[string]*IOCEntry),
		domains:      make(map[string]*IOCEntry),
		urls:         make(map[string]*IOCEntry),
		certThumbprints: make(map[string]*IOCEntry),
		ja3:          make(map[string]*IOCEntry),
	}
	db.loadDefaultIOCs()
	return db
}

func (db *Database) loadDefaultIOCs() {
	defaults := []struct {
		iocType IOCType
		value   string
		source  string
		threat  string
		desc    string
		tags    []string
	}{
		{IOCTypeIP, "192.42.116.41", "internal", "pony", "Pony Loader C2", []string{"malware", "c2"}},
		{IOCTypeIP, "162.216.46.12", "internal", "emotet", "Emotet C2", []string{"malware", "botnet"}},
		{IOCTypeIP, "45.33.32.156", "internal", "scan", "Shodan Scanner", []string{"recon"}},
		{IOCTypeDomain, "coinhive.minero.cc", "internal", "crypto", "CoinHive Miner", []string{"crypto"}},
		{IOCTypeDomain, "cryptoloot.pro", "internal", "crypto", "CryptoLoot Miner", []string{"crypto"}},
		{IOCTypeDomain, "cnc.torrentsnack.com", "internal", "botnet", "Torrent Snack Botnet", []string{"botnet"}},
		{IOCTypeDomain, "update.malware-domain.com", "internal", "malware", "Malware Update Server", []string{"malware"}},
		{IOCTypeJA3, "08b9580f5f5c3e23a6a2a2d40a236f75", "internal", "tor", "Tor Client", []string{"tor", "anonymizer"}},
		{IOCTypeJA3, "c910c8c8a8e8c6e4c2e0c8a4e6a2c0e8", "internal", "emotet", "Emotet Beacon", []string{"malware", "c2"}},
		{IOCTypeJA3, "a0c4e8d2b6f0a4c8e2d6f0c4b8e2a0d6", "internal", "cobaltstrike", "CobaltStrike Beacon", []string{"malware", "c2"}},
	}

	for _, d := range defaults {
		entry := &IOCEntry{
			Type:        d.iocType,
			Value:       d.value,
			Source:      d.source,
			Confidence:  80,
			ThreatType:  d.threat,
			Description: d.desc,
			FirstSeen:   time.Now(),
			LastSeen:    time.Now(),
			Tags:        d.tags,
		}
		db.addEntry(entry)
	}
}

func (db *Database) addEntry(entry *IOCEntry) {
	switch entry.Type {
	case IOCTypeIP:
		db.ips[entry.Value] = entry
	case IOCTypeDomain:
		db.domains[strings.ToLower(entry.Value)] = entry
	case IOCTypeURL:
		db.urls[entry.Value] = entry
	case IOCTypeCert:
		db.certThumbprints[entry.Value] = entry
	case IOCTypeJA3:
		db.ja3[entry.Value] = entry
	}
	db.totalLoaded++
}

func (db *Database) LookupIP(ip string) *IOCEntry {
	db.mu.RLock()
	defer db.mu.RUnlock()
	return db.ips[ip]
}

func (db *Database) LookupDomain(domain string) *IOCEntry {
	db.mu.RLock()
	defer db.mu.RUnlock()

	domain = strings.ToLower(domain)

	if entry, ok := db.domains[domain]; ok {
		return entry
	}

	parts := strings.Split(domain, ".")
	for i := 1; i < len(parts); i++ {
		suffix := strings.Join(parts[i:], ".")
		if entry, ok := db.domains[suffix]; ok {
			return entry
		}
	}

	return nil
}

func (db *Database) LookupJA3(ja3 string) *IOCEntry {
	if ja3 == "" {
		return nil
	}
	db.mu.RLock()
	defer db.mu.RUnlock()
	return db.ja3[ja3]
}

func (db *Database) LookupURL(url string) *IOCEntry {
	db.mu.RLock()
	defer db.mu.RUnlock()
	return db.urls[url]
}

func (db *Database) LookupCert(thumbprint string) *IOCEntry {
	db.mu.RLock()
	defer db.mu.RUnlock()
	return db.certThumbprints[thumbprint]
}

func (db *Database) CheckFlow(srcIP, dstIP, domain string, ja3 string) *IOCEntry {
	if entry := db.LookupIP(dstIP); entry != nil {
		return entry
	}
	if entry := db.LookupIP(srcIP); entry != nil {
		return entry
	}
	if domain != "" {
		if entry := db.LookupDomain(domain); entry != nil {
			return entry
		}
	}
	if ja3 != "" {
		if entry := db.LookupJA3(ja3); entry != nil {
			return entry
		}
	}
	return nil
}

func (db *Database) LoadFromFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	var iocs []IOCEntry
	if err := json.Unmarshal(data, &iocs); err == nil {
		db.mu.Lock()
		for _, entry := range iocs {
			e := entry
			db.addEntry(&e)
		}
		db.mu.Unlock()
		db.lastUpdate = time.Now()
		return nil
	}

	return nil
}

func (db *Database) LoadFromPlainFile(path string, iocType IOCType) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	source := "file:" + path

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		entry := &IOCEntry{
			Type:       iocType,
			Value:      line,
			Source:     source,
			Confidence: 70,
			FirstSeen:  time.Now(),
			LastSeen:   time.Now(),
		}
		db.addEntry(entry)
	}

	return scanner.Err()
}

func (db *Database) Size() int {
	db.mu.RLock()
	defer db.mu.RUnlock()
	return db.totalLoaded
}

func (db *Database) Stats() (ips, domains, urls, certs, ja3s int) {
	db.mu.RLock()
	defer db.mu.RUnlock()
	return len(db.ips), len(db.domains), len(db.urls), len(db.certThumbprints), len(db.ja3)
}

func GenerateCertThumbprint(cert []byte) string {
	hash := sha3.Sum256(cert)
	return fmt.Sprintf("%X", hash[:16])
}

func IsPrivateIP(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	privateBlocks := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"169.254.0.0/16",
		"0.0.0.0/8",
	}
	for _, block := range privateBlocks {
		_, cidr, _ := net.ParseCIDR(block)
		if cidr.Contains(parsed) {
			return true
		}
	}
	return false
}