package main

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/rand"
	"time"

	"ly-flow-platform/pkg/model"
)

// MockFlowData generates random flow data for testing
type MockFlowData struct {
	rng *rand.Rand
}

// NewMockFlowData creates a new mock generator
func NewMockFlowData() *MockFlowData {
	return &MockFlowData{
		rng: rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

// GenerateFlow generates a single random FlowData
func (m *MockFlowData) GenerateFlow() *model.FlowData {
	protocols := []string{"TCP", "UDP"}
	appProtocols := []string{"HTTP", "HTTPS", "DNS", "TLS", "SSH", "FTP", "SMTP", "UNKNOWN"}
	domains := []string{
		"example.com",
		"google.com",
		"api.cloudflare.com",
		"dns.google.com",
		"github.com",
		"updates.microsoft.com",
		"login.microsoftonline.com",
		"pool.miningpool.com",
		"cryptomining.fraud-site.com",
	}
	tlsSNIs := []string{
		"api.github.com",
		"www.google.com",
		"login.live.com",
		"pool.miningpool.com",
		"",
	}

	srcIP := fmt.Sprintf("192.168.%d.%d", m.rng.Intn(256), m.rng.Intn(256))
	dstIP := fmt.Sprintf("%d.%d.%d.%d", m.rng.Intn(256), m.rng.Intn(256), m.rng.Intn(256), m.rng.Intn(256))
	protocol := protocols[m.rng.Intn(len(protocols))]
	appProto := appProtocols[m.rng.Intn(len(appProtocols))]
	domain := domains[m.rng.Intn(len(domains))]

	flow := &model.FlowData{
		ID:          fmt.Sprintf("%s-%d", newUUID(m.rng), m.rng.Int63()),
		Timestamp:   time.Now().Unix(),
		SensorID:    "test-sensor-001",
		SrcIP:       srcIP,
		DstIP:       dstIP,
		SrcPort:     uint16(40000 + m.rng.Intn(25000)),
		DstPort:     uint16(m.pickPort(appProto)),
		Protocol:    protocol,
		AppProtocol: appProto,
		BytesIn:     uint64(m.rng.Int63n(100000)),
		BytesOut:    uint64(m.rng.Int63n(50000)),
		Packets:     uint64(m.rng.Int63n(100)),
		DurationMs:  uint64(m.rng.Int63n(10000)),
		Direction:   "egress",
	}

	// Set domain-related fields based on protocol
	switch appProto {
	case "DNS":
		flow.DNSQuery = domain
		flow.DstPort = 53
	case "HTTP":
		flow.HTTPHost = domain
		flow.DstPort = 80
	case "HTTPS", "TLS":
		flow.TLSSNI = tlsSNIs[m.rng.Intn(len(tlsSNIs))]
		if flow.TLSSNI == "" {
			flow.TLSSNI = domain
		}
		flow.JA3 = generateJA3(m.rng)
		flow.DstPort = 443
	}

	return flow
}

func (m *MockFlowData) pickPort(appProto string) int {
	switch appProto {
	case "HTTP":
		return 80
	case "HTTPS", "TLS":
		return 443
	case "DNS":
		return 53
	case "SSH":
		return 22
	case "FTP":
		return 21
	case "SMTP":
		return 25
	default:
		ports := []int{8080, 8443, 3000, 5000, 9000}
		return ports[m.rng.Intn(len(ports))]
	}
}

// GenerateBatch generates multiple random FlowData
func (m *MockFlowData) GenerateBatch(count int) []*model.FlowData {
	flows := make([]*model.FlowData, count)
	for i := 0; i < count; i++ {
		flows[i] = m.GenerateFlow()
	}
	return flows
}

// GenerateDNSFlow generates a DNS query flow
func (m *MockFlowData) GenerateDNSFlow(domain string) *model.FlowData {
	return &model.FlowData{
		ID:          fmt.Sprintf("%s-%d", newUUID(m.rng), m.rng.Int63()),
		Timestamp:   time.Now().Unix(),
		SensorID:    "test-sensor-001",
		SrcIP:       fmt.Sprintf("192.168.%d.%d", m.rng.Intn(256), m.rng.Intn(256)),
		DstIP:       "8.8.8.8",
		SrcPort:     uint16(40000 + m.rng.Intn(25000)),
		DstPort:     53,
		Protocol:    "UDP",
		AppProtocol: "DNS",
		DNSQuery:    domain,
		BytesIn:     uint64(m.rng.Int63n(500)),
		BytesOut:    uint64(m.rng.Int63n(1000)),
		Packets:     uint64(m.rng.Int63n(10)),
		DurationMs:  uint64(m.rng.Int63n(1000)),
		Direction:   "egress",
	}
}

// GenerateTLSFlow generates a TLS flow with SNI
func (m *MockFlowData) GenerateTLSFlow(sni string, isMalicious bool) *model.FlowData {
	flow := &model.FlowData{
		ID:          fmt.Sprintf("%s-%d", newUUID(m.rng), m.rng.Int63()),
		Timestamp:   time.Now().Unix(),
		SensorID:    "test-sensor-001",
		SrcIP:       fmt.Sprintf("192.168.%d.%d", m.rng.Intn(256), m.rng.Intn(256)),
		DstIP:       "1.2.3.4",
		SrcPort:     uint16(40000 + m.rng.Intn(25000)),
		DstPort:     443,
		Protocol:    "TCP",
		AppProtocol: "HTTPS",
		TLSSNI:      sni,
		JA3:         generateJA3(m.rng),
		BytesIn:     uint64(m.rng.Int63n(50000)),
		BytesOut:    uint64(m.rng.Int63n(20000)),
		Packets:     uint64(m.rng.Int63n(50)),
		DurationMs:  uint64(m.rng.Int63n(5000)),
		Direction:   "egress",
	}

	if isMalicious {
		flow.HTTPHost = sni
	}

	return flow
}

// generateJA3 generates a random JA3 hash
func generateJA3(rng *rand.Rand) string {
	data := make([]byte, 16)
	rng.Read(data)
	hash := md5.Sum(data)
	return hex.EncodeToString(hash[:])
}

// newUUID generates a simple UUID-like string
func newUUID(rng *rand.Rand) string {
	data := make([]byte, 16)
	rng.Read(data)
	return fmt.Sprintf("%x-%x-%x-%x-%x",
		data[0:4], data[4:6], data[6:8], data[8:10], data[10:16])
}

// PrintFlowJSON prints flow data as JSON for testing
func PrintFlowJSON(flow *model.FlowData) {
	data, _ := json.MarshalIndent(flow, "", "  ")
	fmt.Println(string(data))
}

// PrintBatchJSON prints batch of flows as JSON
func PrintBatchJSON(flows []*model.FlowData) {
	data, _ := json.MarshalIndent(flows, "", "  ")
	fmt.Println(string(data))
}

// MockMain runs mock data generation for testing
func MockMain() {
	m := NewMockFlowData()

	fmt.Println("=== Mock Flow Data Generator ===")
	fmt.Println()

	// Generate sample flows
	fmt.Println("--- Sample HTTP Flow ---")
	PrintFlowJSON(m.GenerateFlow())

	fmt.Println("\n--- Sample DNS Flow ---")
	PrintFlowJSON(m.GenerateDNSFlow("cryptomining-pool.com"))

	fmt.Println("\n--- Sample TLS Flow ---")
	PrintFlowJSON(m.GenerateTLSFlow("pool.miningpool.com", true))

	fmt.Println("\n--- Batch of 5 Flows ---")
	PrintBatchJSON(m.GenerateBatch(5))
}
