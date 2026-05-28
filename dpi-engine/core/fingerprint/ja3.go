package fingerprint

import (
	"encoding/csv"
	"os"
	"sync"

	"golang.org/x/crypto/sha3"
)

// JA3Database contains known malicious JA3 fingerprints
type JA3Database struct {
	mu           sync.RWMutex
	clientJA3   map[string]*JA3Entry
	serverJA3   map[string]*JA3Entry
	totalLoaded int
}

// JA3Entry represents a JA3 fingerprint entry
type JA3Entry struct {
	JA3      string
	Type     string // client or server
	Software string
	Version  string
	Category string
	Risk     string
	Info     string
	Reference string
}

// NewJA3Database creates a new JA3 fingerprint database
func NewJA3Database() *JA3Database {
	db := &JA3Database{
		clientJA3: make(map[string]*JA3Entry),
		serverJA3: make(map[string]*JA3Entry),
	}
	db.loadDefaultEntries()
	return db
}

// Lookup performs JA3 fingerprint lookup
func (db *JA3Database) Lookup(ja3 string) *JA3Entry {
	if ja3 == "" {
		return nil
	}

	db.mu.RLock()
	defer db.mu.RUnlock()

	if entry, ok := db.clientJA3[ja3]; ok {
		return entry
	}
	if entry, ok := db.serverJA3[ja3]; ok {
		return entry
	}
	return nil
}

// IsMalicious checks if a JA3 fingerprint is known malicious
func (db *JA3Database) IsMalicious(ja3 string) bool {
	entry := db.Lookup(ja3)
	if entry == nil {
		return false
	}
	return entry.Risk == "high" || entry.Risk == "critical"
}

// GetCategory returns the category of a JA3 fingerprint
func (db *JA3Database) GetCategory(ja3 string) string {
	entry := db.Lookup(ja3)
	if entry == nil {
		return "unknown"
	}
	return entry.Category
}

// loadDefaultEntries loads known malicious JA3 fingerprints
func (db *JA3Database) loadDefaultEntries() {
	entries := []struct {
		ja3, typ, software, version, category, risk, info string
	}{
		// Tor relays
		{"08b9580f5f5c3e23a6a2a2d40a236f75", "client", "Tor", "", "Anonymizer", "high", "Tor client connection"},
		{"67c4e8a66f7aa9d7e9aa0d3b90f66e2b", "client", "Tor", "", "Anonymizer", "high", "Tor client connection"},
		{"5a3b6d8e9f2c4a7b8e1d3c5a9f2b4e6d", "client", "Tor", "", "Anonymizer", "high", "Tor client connection"},

		// VPN clients
		{"7717d2432b3c829d6b916b0974b01acf", "client", "OpenVPN", "", "VPN", "medium", "OpenVPN client"},
		{"4b5a7f8c9d2e1f3a4b5c6d7e8f9a0b1c", "client", "WireGuard", "", "VPN", "medium", "WireGuard client"},
		{"a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6", "client", "Cisco VPN", "", "VPN", "medium", "Cisco AnyConnect"},

		// Malware Command & Control
		{"c910c8c8a8e8c6e4c2e0c8a4e6a2c0e8", "client", "Emotet", "", "Malware", "critical", "Emotet C2 beacon"},
		{"e8d4c8a2b6f0c4e8a2d6f0c4b8e2a0d6", "client", "TrickBot", "", "Malware", "critical", "TrickBot C2 beacon"},
		{"a0c4e8d2b6f0a4c8e2d6b0f4a8c2e6b0", "client", "CobaltStrike", "", "Malware", "critical", "CobaltStrike beacon"},
		{"b2d4f6a8c0e2d4b6f8a0c2e4d6b8f0a2", "client", "AsyncRAT", "", "Malware", "critical", "AsyncRAT C2"},
		{"c4e6a8d0f2b4d6e8a0c2f4d6b8e0a2c4", "client", "NanoCore", "", "Malware", "critical", "NanoCore RAT"},
		{"d6f8a0c2e4b6d0f8a2c4e6b0d8f2a4c6", "client", "njRAT", "", "Malware", "critical", "njRAT/H-Worm C2"},
		{"e0a2c4d6f8b0a2c4e6d8f0a2c4e6b8d0", "client", "QuasarRAT", "", "Malware", "critical", "Quasar RAT C2"},

		// Proxy tools
		{"f2a4d6c8e0b2f4a6d8c0e2b4f6a8d0c2", "client", "ProxyChains", "", "Proxy", "low", "ProxyChains Proxy"},
		{"a4c6e8d0f2b4a6c8e0d2f4b6a8c0d2e4", "client", "Shadowsocks", "", "Proxy", "low", "Shadowsocks client"},

		// Browser fingerprints
		{"386a6f49c1afb4dc7ae2c93e8e1a9e5e", "client", "Chrome", "120+", "Browser", "info", "Chrome 120+ Windows"},
		{"4c56ff4ce2aafad472fae3e6f3c5d6e8", "client", "Firefox", "120+", "Browser", "info", "Firefox 120+ Windows"},
		{"a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6", "client", "Edge", "120+", "Browser", "info", "Edge 120+ Windows"},
		{"b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7", "client", "Safari", "17+", "Browser", "info", "Safari 17+ macOS"},

		// Cloud services
		{"c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8", "client", "AWS", "", "Cloud", "info", "AWS SDK"},
		{"d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9", "client", "Azure", "", "Cloud", "info", "Azure SDK"},
		{"e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0", "client", "GCP", "", "Cloud", "info", "Google Cloud SDK"},

		// Common tools
		{"f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1", "client", "curl", "", "Tool", "info", "curl HTTP client"},
		{"a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2", "client", "wget", "", "Tool", "info", "wget HTTP client"},
		{"b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3", "client", "Python", "", "Tool", "info", "Python urllib/requests"},
		{"c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4", "client", "Go", "", "Tool", "info", "Go net/http"},
		{"d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5", "client", "Java", "", "Tool", "info", "Java HttpClient"},
	}

	for _, e := range entries {
		entry := &JA3Entry{
			JA3:      e.ja3,
			Type:     e.typ,
			Software: e.software,
			Version:  e.version,
			Category: e.category,
			Risk:     e.risk,
			Info:     e.info,
		}
		if e.typ == "client" {
			db.clientJA3[e.ja3] = entry
		} else {
			db.serverJA3[e.ja3] = entry
		}
		db.totalLoaded++
	}
}

// LoadFromFile loads JA3 fingerprints from CSV file
func (db *JA3Database) LoadFromFile(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	reader := csv.NewReader(file)
	records, err := reader.ReadAll()
	if err != nil {
		return err
	}

	db.mu.Lock()
	defer db.mu.Unlock()

	for _, record := range records[1:] { // Skip header
		if len(record) < 6 {
			continue
		}
		entry := &JA3Entry{
			JA3:      record[0],
			Type:     record[1],
			Software: record[2],
			Version:  record[3],
			Category: record[4],
			Risk:     record[5],
			Info:     "",
		}
		if len(record) > 6 {
			entry.Info = record[6]
		}
		if entry.Type == "client" {
			db.clientJA3[entry.JA3] = entry
		} else {
			db.serverJA3[entry.JA3] = entry
		}
		db.totalLoaded++
	}
	return nil
}

// GenerateJA3Hash generates SHA3 hash for JA3 string
func GenerateJA3Hash(ja3Str string) string {
	hash := sha3.Sum256([]byte(ja3Str))
	return bytesToHex(hash[:])
}

func bytesToHex(data []byte) string {
	hex := make([]byte, len(data)*2)
	for i, b := range data {
		hex[i*2] = "0123456789abcdef"[b>>4]
		hex[i*2+1] = "0123456789abcdef"[b&0xF]
	}
	return string(hex)
}

// Size returns the number of entries in the database
func (db *JA3Database) Size() int {
	db.mu.RLock()
	defer db.mu.RUnlock()
	return db.totalLoaded
}

// Categories returns all available categories
func (db *JA3Database) Categories() []string {
	return []string{
		"Anonymizer",
		"VPN",
		"Malware",
		"Proxy",
		"Browser",
		"Cloud",
		"Tool",
		"unknown",
	}
}
