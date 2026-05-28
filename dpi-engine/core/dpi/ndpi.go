package dpi

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// Protocol ID definitions (nDPI compatible)
const (
	ProtocolUnknown     = 0
	ProtocolDNS         = 1
	ProtocolHTTP        = 2
	ProtocolHTTPS       = 3
	ProtocolTLS         = 4
	ProtocolSSH          = 5
	ProtocolFTP          = 6
	ProtocolSMTP        = 7
	ProtocolSMB          = 8
	ProtocolNTP          = 9
	ProtocolDHCP         = 10
	ProtocolRedis        = 11
	ProtocolMongoDB      = 12
	ProtocolMySQL        = 13
	ProtocolPostgreSQL   = 14
	ProtocolMSSQL        = 15
	ProtocolOracle       = 16
	ProtocolHTTPProxy    = 17
	ProtocolIRC          = 18
	ProtocolIRC_2        = 18
	ProtocolTeamViewer   = 19
	Protocolbittorrent   = 20
	Protocolbittorrent_2 = 20
	ProtocolNOPERATION   = 21
	ProtocolNetFlow      = 22
	ProtocolsHTTP_HTTP   = 23
	ProtocolSNMP         = 24
	ProtocolTLS_2        = 25
	ProtocolUPnP         = 26
	ProtocolSSDP         = 27
	ProtocolWorldOfWarcraft = 28
	ProtocolPostgres     = 29
	ProtocolMySQL_2      = 30
	ProtocolTLS_3         = 31
)

// Protocol names map
var ProtocolNames = map[int]string{
	ProtocolUnknown:    "UNKNOWN",
	ProtocolDNS:        "DNS",
	ProtocolHTTP:       "HTTP",
	ProtocolHTTPS:      "HTTPS",
	ProtocolTLS:        "TLS",
	ProtocolSSH:        "SSH",
	ProtocolFTP:        "FTP",
	ProtocolSMTP:       "SMTP",
	ProtocolSMB:        "SMB",
	ProtocolNTP:        "NTP",
	ProtocolDHCP:       "DHCP",
	ProtocolRedis:      "Redis",
	ProtocolMongoDB:    "MongoDB",
	ProtocolMySQL:      "MySQL",
	ProtocolPostgreSQL: "PostgreSQL",
	ProtocolMSSQL:      "MSSQL",
	ProtocolOracle:     "Oracle",
	ProtocolHTTPProxy:  "HTTP_PROXY",
	ProtocolIRC:        "IRC",
	ProtocolTeamViewer: "TeamViewer",
	Protocolbittorrent: "BitTorrent",
	ProtocolPostgres:   "PostgreSQL",
	ProtocolMySQL_2:    "MySQL",
}

const wave2EnableLegacyProtocolDetectors = false

func isWave2AllowedProtocol(protocol int) bool {
	switch protocol {
	case ProtocolHTTP, ProtocolDNS, ProtocolTLS:
		return true
	default:
		return false
	}
}

// NDPIConfidentLevel indicates detection confidence
type NDPIConfidentLevel int

const (
	NDPIConfidenceNotPossible NDPIConfidentLevel = 0
	NDPIConfidenceMaybe       NDPIConfidentLevel = 1
	NDPIConfidenceUsuallyYes  NDPIConfidentLevel = 2
	NDPIConfidenceFlowOnly    NDPIConfidentLevel = 3
	NDPIConfidenceDimitri     NDPIConfidentLevel = 4
)

// FlowInfo represents detected flow information
type FlowInfo struct {
	Protocol    int
	ProtocolName string
	Confidence   NDPIConfidentLevel
	Category     int
	CategoryName string
	MasterProtocol int
	AppProtocolName string

	// TLS specific
	TLSVersion    string
	TLSSNI        string
	TLSIssuerCN   string
	TLSSubjectCN  string
	JA3           string
	JA3Server     string

	// DNS specific
	DNSQuery       string
	DNSNXDomain    bool
	DNSType        string

	// HTTP specific
	HTTPMethod     string
	HTTPHost       string
	HTTPUri        string
	HTTPUserAgent  string
	HTTPContentType string
	HTTPStatusCode uint16

	// SSH specific
	SSHClientProtoVersion string
	SSHServerProtoVersion string
	SSHClientSoftwareVersion string
	SSHServerSoftwareVersion string
	SSHEncryptionAlg string
	SSHAuthMethod    string

	// Generic
	BitTorrentHash string
	Flowscore       int

	// Meta
	EstimatedBytes uint64
	LastUpdate      time.Time
}

// NDPIProcessor is a simplified nDPI-like protocol detection engine
type NDPIProcessor struct {
	flows     map[string]*FlowEntry
	mu        sync.RWMutex
	ticker     *time.Ticker
	stopCh    chan struct{}
	packets    uint64
	flowsDetected uint64

	// Detection callbacks
	callbacks map[string]func(*FlowInfo)
}

type FlowEntry struct {
	Key          string
	FirstPacket  time.Time
	LastSeen     time.Time
	Packets      uint64
	Bytes        uint64
	SrcIP, DstIP net.IP
	SrcPort, DstPort uint16
	Layer4Protocol uint8

	Info *FlowInfo

	// Detection state
	state         int // 0=initial, 1=L4 detected, 2=L7 detected
	l7Detected    bool
	protocolStack []int

	// Protocol specific
	httpBuffer    []byte
	tlsBuffer     []byte
	dnsBuffer      []byte
	sshBuffer      []byte
}

// NewNDPIProcessor creates a new nDPI-style protocol processor
func NewNDPIProcessor() *NDPIProcessor {
	p := &NDPIProcessor{
		flows:    make(map[string]*FlowEntry),
		stopCh:   make(chan struct{}),
		callbacks: make(map[string]func(*FlowInfo)),
	}
	p.ticker = time.NewTicker(5 * time.Minute)
	go p.cleanup()
	return p
}

// Start begins the protocol detection processor
func (p *NDPIProcessor) Start() {
	go p.run()
}

// Stop stops the processor
func (p *NDPIProcessor) Stop() {
	close(p.stopCh)
	p.ticker.Stop()
}

// ProcessPacket processes a packet and returns detected protocol info
func (p *NDPIProcessor) ProcessPacket(data []byte) *FlowInfo {
	atomic.AddUint64(&p.packets, 1)

	packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)
	ipLayer := packet.NetworkLayer()
	if ipLayer == nil {
		return nil
	}

	ip, ok := ipLayer.(*layers.IPv4)
	if !ok {
		return nil
	}

	// Find transport layer
	var srcPort, dstPort uint16
	var l4Protocol uint8
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		srcPort = uint16(tcp.SrcPort)
		dstPort = uint16(tcp.DstPort)
		l4Protocol = 6 // TCP
	} else {
		udpLayer := packet.Layer(layers.LayerTypeUDP)
		if udpLayer != nil {
			udp, _ := udpLayer.(*layers.UDP)
			srcPort = uint16(udp.SrcPort)
			dstPort = uint16(udp.DstPort)
			l4Protocol = 17 // UDP
		} else {
			return nil
		}
	}

	// Build flow key
	flowKey := buildFlowKey(ip.SrcIP.String(), srcPort, ip.DstIP.String(), dstPort, l4Protocol)

	// Get or create flow entry
	p.mu.Lock()
	entry, exists := p.flows[flowKey]
	if !exists {
		entry = &FlowEntry{
			Key:         flowKey,
			FirstPacket: time.Now(),
			SrcIP:       ip.SrcIP,
			DstIP:       ip.DstIP,
			SrcPort:     srcPort,
			DstPort:     dstPort,
			Layer4Protocol: l4Protocol,
			Info:        &FlowInfo{},
		}
		p.flows[flowKey] = entry
		p.flowsDetected++
	}
	p.mu.Unlock()

	entry.LastSeen = time.Now()
	entry.Packets++
	entry.Bytes += uint64(len(data))

	// Layer 7 detection
	if !entry.l7Detected {
		p.detectL7Protocol(entry, packet, data)
	}

	entry.Info.LastUpdate = time.Now()
	entry.Info.EstimatedBytes = entry.Bytes

	return entry.Info
}

// detectL7Protocol performs layer 7 protocol detection
func (p *NDPIProcessor) detectL7Protocol(entry *FlowEntry, packet gopacket.Packet, data []byte) {
	// Get payload
	var payload []byte
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		if tcp, ok := tcpLayer.(*layers.TCP); ok {
			payload = tcp.Payload
		}
	} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		if udp, ok := udpLayer.(*layers.UDP); ok {
			payload = udp.Payload
		}
	}

	if len(payload) == 0 {
		return
	}

	if entry.Info.ProtocolName == "" {
		entry.Info.ProtocolName = ProtocolNames[ProtocolUnknown]
	}

	protocol := p.detectByPort(entry.SrcPort, entry.DstPort, entry.Layer4Protocol)
	if protocol != ProtocolUnknown && isWave2AllowedProtocol(protocol) {
		entry.Info.Protocol = protocol
		entry.Info.ProtocolName = ProtocolNames[protocol]
		entry.Info.Confidence = NDPIConfidenceFlowOnly
	}

	if entry.Layer4Protocol == 6 { // TCP
		p.detectHTTPCustom(entry, payload)
		if entry.Info.Protocol == ProtocolUnknown {
			p.detectTLS(entry, payload)
		}
		if wave2EnableLegacyProtocolDetectors && entry.Info.Protocol == ProtocolUnknown {
			p.detectSSH(entry, payload)
		}
		if wave2EnableLegacyProtocolDetectors && entry.Info.Protocol == ProtocolUnknown {
			p.detectMySQL(entry, payload)
		}
		if wave2EnableLegacyProtocolDetectors && entry.Info.Protocol == ProtocolUnknown {
			p.detectPostgreSQL(entry, payload)
		}
		if wave2EnableLegacyProtocolDetectors && entry.Info.Protocol == ProtocolUnknown {
			p.detectRedis(entry, payload)
		}
	} else if entry.Layer4Protocol == 17 { // UDP
		p.detectDNS(entry, payload)
		if wave2EnableLegacyProtocolDetectors && entry.Info.Protocol == ProtocolUnknown {
			p.detectNTP(entry, payload)
		}
		if wave2EnableLegacyProtocolDetectors && entry.Info.Protocol == ProtocolUnknown {
			p.detectDHCP(entry, payload)
		}
	}

	if entry.Info.Protocol != ProtocolUnknown && !isWave2AllowedProtocol(entry.Info.Protocol) {
		entry.Info.Protocol = ProtocolUnknown
		entry.Info.ProtocolName = ProtocolNames[ProtocolUnknown]
		entry.Info.Confidence = NDPIConfidenceNotPossible
	}

	// Mark as detected if protocol found
	if entry.Info.Protocol != ProtocolUnknown {
		entry.l7Detected = true
		entry.Info.Category = p.getCategory(entry.Info.Protocol)
		entry.Info.CategoryName = p.getCategoryName(entry.Info.Category)
	}
}

// detectByPort performs port-based protocol detection
func (p *NDPIProcessor) detectByPort(srcPort, dstPort uint16, proto uint8) int {
	portMap := map[uint16]int{
		53:   ProtocolDNS,
		80:   ProtocolHTTP,
		443:  ProtocolTLS,
		8080: ProtocolHTTP,
		8443: ProtocolTLS,
	}

	if p, ok := portMap[dstPort]; ok {
		return p
	}
	if p, ok := portMap[srcPort]; ok {
		return p
	}
	return ProtocolUnknown
}

// detectTLS detects TLS protocol and extracts JA3 fingerprint
func (p *NDPIProcessor) detectTLS(entry *FlowEntry, payload []byte) {
	if len(payload) < 5 {
		return
	}

	// TLS record layer detection
	contentType := payload[0]
	// TLS 1.0/1.1: ContentType(1) + Version(2) + Length(2)
	// TLS 1.2+: Same structure

	if contentType == 0x16 { // Handshake
		if len(payload) >= 43 {
			// Version
			version := fmt.Sprintf("%d.%d", payload[1], payload[2])

			// Check for TLS Client Hello
			if payload[5] == 0x01 { // Client Hello
				entry.Info.TLSVersion = version
				entry.Info.Protocol = ProtocolTLS
				entry.Info.ProtocolName = "TLS"
				entry.Info.Confidence = NDPIConfidenceUsuallyYes
				entry.Info.TLSSNI = p.extractTLSSNI(payload)

				// Extract JA3 fingerprint
				ja3 := p.extractJA3(payload)
				entry.Info.JA3 = ja3
			}
		}
	}
}

func (p *NDPIProcessor) extractTLSSNI(data []byte) string {
	if len(data) < 9 || data[0] != 0x16 || data[5] != 0x01 {
		return ""
	}

	offset := 9
	if offset+2 > len(data) {
		return ""
	}
	offset += 2
	if offset+32 > len(data) {
		return ""
	}
	offset += 32
	if offset+1 > len(data) {
		return ""
	}
	sessionIDLen := int(data[offset])
	offset++
	if offset+sessionIDLen > len(data) {
		return ""
	}
	offset += sessionIDLen

	if offset+2 > len(data) {
		return ""
	}
	cipherLen := int(data[offset])<<8 | int(data[offset+1])
	offset += 2
	if offset+cipherLen > len(data) {
		return ""
	}
	offset += cipherLen

	if offset+1 > len(data) {
		return ""
	}
	compressionMethodsLen := int(data[offset])
	offset++
	if offset+compressionMethodsLen > len(data) {
		return ""
	}
	offset += compressionMethodsLen

	if offset+2 > len(data) {
		return ""
	}
	extLen := int(data[offset])<<8 | int(data[offset+1])
	offset += 2
	extEnd := offset + extLen
	if extEnd > len(data) {
		extEnd = len(data)
	}

	for offset+4 <= extEnd {
		extType := int(data[offset])<<8 | int(data[offset+1])
		extDataLen := int(data[offset+2])<<8 | int(data[offset+3])
		offset += 4
		if offset+extDataLen > extEnd {
			break
		}

		if extType == 0 {
			if extDataLen < 5 {
				return ""
			}
			nameListLen := int(data[offset])<<8 | int(data[offset+1])
			listOffset := offset + 2
			listEnd := listOffset + nameListLen
			if listEnd > offset+extDataLen {
				listEnd = offset + extDataLen
			}
			for listOffset+3 <= listEnd {
				nameType := data[listOffset]
				nameLen := int(data[listOffset+1])<<8 | int(data[listOffset+2])
				listOffset += 3
				if listOffset+nameLen > listEnd {
					break
				}
				if nameType == 0 && nameLen > 0 {
					return string(data[listOffset : listOffset+nameLen])
				}
				listOffset += nameLen
			}
			return ""
		}

		offset += extDataLen
	}

	return ""
}

// extractJA3 extracts TLS client hello fingerprint
func (p *NDPIProcessor) extractJA3(data []byte) string {
	if len(data) < 43 {
		return ""
	}

	// JA3 format: TLS version, cipher suites, extensions, elliptic curves, ec point formats
	var parts []string

	// TLS Version (2 bytes)
	parts = append(parts, fmt.Sprintf("%d%d", data[1], data[2]))

	// Random (32 bytes)
	// Skip and look for cipher suites

	// Session ID length (1 byte) + session ID
	offset := 43
	if offset >= len(data) {
		return ""
	}
	sessionIDLen := int(data[offset])
	offset += 1 + sessionIDLen

	// Cipher suites length (2 bytes)
	if offset+2 >= len(data) {
		return ""
	}
	cipherLen := int(data[offset])<<8 | int(data[offset+1])
	offset += 2

	// Cipher suites (2 bytes each)
	cipherCount := cipherLen / 2
	ciphers := make([]string, 0, cipherCount)
	for i := 0; i < cipherCount && offset+2 <= len(data); i++ {
		cipher := fmt.Sprintf("%d%d", data[offset], data[offset+1])
		ciphers = append(ciphers, cipher)
		offset += 2
	}
	if len(ciphers) > 0 {
		parts = append(parts, join(ciphers, "-"))
	}

	// Extensions
	if offset >= len(data) {
		return join(parts, ",")
	}
	extLen := int(data[offset])<<8 | int(data[offset+1])
	offset += 2

	extEnd := offset + extLen
	extensions := make([]string, 0)
	for offset+4 < extEnd && offset+4 < len(data) {
		extType := int(data[offset])<<8 | int(data[offset+1])
		extensions = append(extensions, fmt.Sprintf("%d", extType))
		extDataLen := int(data[offset+2])<<8 | int(data[offset+3])
		offset += 4 + extDataLen
	}
	if len(extensions) > 0 {
		parts = append(parts, join(extensions, "-"))
	}

	// Elliptic curves
	if offset+2 >= len(data) {
		return join(parts, ",")
	}
	curveLen := int(data[offset])<<8 | int(data[offset+1])
	offset += 2
	curves := make([]string, 0, curveLen/2)
	for i := 0; i < curveLen/2 && offset+2 <= len(data); i++ {
		curves = append(curves, fmt.Sprintf("%d%d", data[offset], data[offset+1]))
		offset += 2
	}
	if len(curves) > 0 {
		parts = append(parts, join(curves, "-"))
	}

	// EC point formats
	if offset+1 >= len(data) {
		return join(parts, ",")
	}
	formatLen := int(data[offset])
	offset++
	formats := make([]string, 0, formatLen)
	for i := 0; i < formatLen && offset < len(data); i++ {
		formats = append(formats, fmt.Sprintf("%d", data[offset]))
		offset++
	}
	if len(formats) > 0 {
		parts = append(parts, join(formats, "-"))
	}

	return join(parts, ",")
}

func join(arr []string, sep string) string {
	if len(arr) == 0 {
		return ""
	}
	result := arr[0]
	for i := 1; i < len(arr); i++ {
		result += sep + arr[i]
	}
	return result
}

// detectHTTP performs HTTP detection and extraction
func (p *NDPIProcessor) detectHTTPCustom(entry *FlowEntry, payload []byte) {
	if len(payload) < 4 {
		return
	}

	// HTTP request methods
	httpMethods := []string{"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT", "TRACE"}
	for _, method := range httpMethods {
		if len(payload) >= len(method) && string(payload[:len(method)]) == method {
			entry.Info.Protocol = ProtocolHTTP
			entry.Info.ProtocolName = "HTTP"
			entry.Info.Confidence = NDPIConfidenceDimitri

			// Parse HTTP headers
			headers := parseHTTPHeaders(string(payload))
			if host, ok := headers["Host"]; ok {
				entry.Info.HTTPHost = host
			}
			if ua, ok := headers["User-Agent"]; ok {
				entry.Info.HTTPUserAgent = ua
			}
			return
		}
	}

	// HTTP response detection
	if len(payload) >= 8 && string(payload[:4]) == "HTTP" {
		// Try to parse status code
		if len(payload) >= 12 {
			statusCode := string(payload[9:12])
			var code uint16
			fmt.Sscanf(statusCode, "%d", &code)
			entry.Info.HTTPStatusCode = code
		}
	}
}

// parseHTTPHeaders parses HTTP headers from payload
func parseHTTPHeaders(data string) map[string]string {
	headers := make(map[string]string)
	lines := make([]string, 0, 10)

	// Split by lines
	start := 0
	for i := 0; i < len(data) && i-start < 4096; i++ {
		if data[i] == '\n' {
			line := data[start:i]
			if len(line) > 0 && line[len(line)-1] == '\r' {
				line = line[:len(line)-1]
			}
			lines = append(lines, line)
			start = i + 1
			if line == "" {
				break
			}
		}
	}

	for _, line := range lines[1:] { // Skip request line
		colon := -1
		for i, c := range line {
			if c == ':' {
				colon = i
				break
			}
		}
		if colon > 0 {
			key := line[:colon]
			value := line[colon+1:]
			// Trim leading space
			for len(value) > 0 && value[0] == ' ' {
				value = value[1:]
			}
			headers[key] = value
		}
	}
	return headers
}

// detectDNS performs DNS protocol detection
func (p *NDPIProcessor) detectDNS(entry *FlowEntry, payload []byte) {
	if len(payload) < 12 {
		return
	}

	// DNS header: ID(2) + Flags(2) + Questions(2) + Answers(2) + Authority(2) + Additional(2)
	flags := uint16(payload[2])<<8 | uint16(payload[3])

	// Check if it's a query or response
	isQuery := (flags & 0x8000) == 0

	if isQuery {
		entry.Info.Protocol = ProtocolDNS
		entry.Info.ProtocolName = "DNS"
		entry.Info.Confidence = NDPIConfidenceDimitri

		// Parse query name
		query := parseDNSQuery(payload[12:])
		if query != "" {
			entry.Info.DNSQuery = query
		}
	} else {
		// Response
		entry.Info.Protocol = ProtocolDNS
		entry.Info.ProtocolName = "DNS"
		entry.Info.Confidence = NDPIConfidenceDimitri

		// Check NXDOMAIN
		if flags&0x0003 == 3 {
			entry.Info.DNSNXDomain = true
		}
	}
}

// parseDNSQuery parses DNS query name from payload
func parseDNSQuery(data []byte) string {
	if len(data) == 0 {
		return ""
	}

	var name string
	pos := 0
	labels := 0

	for {
		if pos >= len(data) {
			break
		}
		length := int(data[pos])
		if length == 0 {
			pos++
			break
		}
		// Check for compression pointer
		if length >= 0xc0 {
			break
		}
		pos++
		if pos+length > len(data) {
			break
		}
		if labels > 0 {
			name += "."
		}
		name += string(data[pos : pos+length])
		pos += length
		labels++
		if labels > 10 {
			break
		}
	}
	return name
}

// detectSSH performs SSH protocol detection
func (p *NDPIProcessor) detectSSH(entry *FlowEntry, payload []byte) {
	// SSH protocol identification: "SSH-" prefix
	if len(payload) >= 4 && string(payload[:4]) == "SSH-" {
		entry.Info.Protocol = ProtocolSSH
		entry.Info.ProtocolName = "SSH"
		entry.Info.Confidence = NDPIConfidenceDimitri

		// Extract version string
		version := string(payload[4:])
		for i, c := range version {
			if c == '\n' || c == '\r' {
				version = version[:i]
				break
			}
		}
		if strings.HasPrefix(version, "1.") || strings.HasPrefix(version, "2.") {
			entry.Info.SSHServerProtoVersion = version
		}
	}
}

// detectMySQL performs MySQL protocol detection
func (p *NDPIProcessor) detectMySQL(entry *FlowEntry, payload []byte) {
	if len(payload) < 5 {
		return
	}

	// MySQL protocol: first byte is packet length (3 bytes) + sequence ID (1 byte)
	length := int(payload[0]) | int(payload[1])<<8 | int(payload[2])<<16
	if length > 0 && length < 65536 {
		packetType := payload[4]
		// 0x01 = ERR, 0xFE = OK, 0xFF = handshake or auth
		if packetType == 0xFF || packetType == 0xFE || packetType == 0x00 {
			// Could be MySQL
			if length > 32 {
				entry.Info.Protocol = ProtocolMySQL
				entry.Info.ProtocolName = "MySQL"
				entry.Info.Confidence = NDPIConfidenceUsuallyYes
			}
		}
	}
}

// detectPostgreSQL performs PostgreSQL protocol detection
func (p *NDPIProcessor) detectPostgreSQL(entry *FlowEntry, payload []byte) {
	if len(payload) < 5 {
		return
	}

	// PostgreSQL protocol: starts with length (4 bytes) + type
	// Types: 'p' = password, 'Q' = query, 'H' = SSL request
	if payload[4] == 'p' || payload[4] == 'Q' || payload[4] == 'H' {
		entry.Info.Protocol = ProtocolPostgreSQL
		entry.Info.ProtocolName = "PostgreSQL"
		entry.Info.Confidence = NDPIConfidenceUsuallyYes

		if payload[4] == 'Q' && len(payload) > 5 {
			// Extract query
			query := string(payload[5:])
			for i := 0; i < len(query); i++ {
				if query[i] == 0 {
					entry.Info.HTTPMethod = query[:i]
					break
				}
			}
		}
	}
}

// detectRedis performs Redis protocol detection
func (p *NDPIProcessor) detectRedis(entry *FlowEntry, payload []byte) {
	if len(payload) == 0 {
		return
	}

	// Redis protocol: RESP
	// Commands start with *, $, +, -, :
	if payload[0] == '*' || payload[0] == '$' {
		entry.Info.Protocol = ProtocolRedis
		entry.Info.ProtocolName = "Redis"
		entry.Info.Confidence = NDPIConfidenceUsuallyYes
	}
}

// detectNTP performs NTP protocol detection
func (p *NDPIProcessor) detectNTP(entry *FlowEntry, payload []byte) {
	if len(payload) < 48 {
		return
	}

	// NTP packet: first byte is LI (2 bits) + Version (3 bits) + Mode (3 bits)
	version := (payload[0] >> 3) & 0x07
	mode := payload[0] & 0x07

	// Valid NTP: version 1-4, mode 1-6
	if version >= 1 && version <= 4 && mode >= 1 && mode <= 6 {
		entry.Info.Protocol = ProtocolNTP
		entry.Info.ProtocolName = "NTP"
		entry.Info.Confidence = NDPIConfidenceDimitri
	}
}

// detectDHCP performs DHCP protocol detection
func (p *NDPIProcessor) detectDHCP(entry *FlowEntry, payload []byte) {
	if len(payload) < 240 {
		return
	}

	// DHCP: magic cookie = 0x63825363 at offset 236
	if len(payload) >= 240 && payload[236] == 0x63 && payload[237] == 0x82 && payload[238] == 0x53 && payload[239] == 0x63 {
		entry.Info.Protocol = ProtocolDHCP
		entry.Info.ProtocolName = "DHCP"
		entry.Info.Confidence = NDPIConfidenceDimitri
	}
}

// getCategory returns category for protocol
func (p *NDPIProcessor) getCategory(protocol int) int {
	categories := map[int]int{
		ProtocolDNS:  1,
		ProtocolHTTP: 2,
		ProtocolTLS:  7,
	}
	if cat, ok := categories[protocol]; ok {
		return cat
	}
	return 0
}

// getCategoryName returns category name
func (p *NDPIProcessor) getCategoryName(category int) string {
	names := map[int]string{
		0:  "Unspecified",
		1:  "Network",
		2:  "Web",
		3:  "Email",
		4:  "Chat",
		5:  "Streaming",
		6:  "Game",
		7:  "Encrypted",
		8:  "VPN",
		9:  "Directory",
		10: "Database",
		11: "Voice",
		12: "Video",
	}
	if name, ok := names[category]; ok {
		return name
	}
	return "Unknown"
}

// buildFlowKey creates a unique flow key
func buildFlowKey(srcIP string, srcPort uint16, dstIP string, dstPort uint16, proto uint8) string {
	return fmt.Sprintf("%s:%d-%s:%d-%d", srcIP, srcPort, dstIP, dstPort, proto)
}

func (p *NDPIProcessor) run() {
	for {
		select {
		case <-p.stopCh:
			return
		case <-p.ticker.C:
			p.cleanup()
		}
	}
}

func (p *NDPIProcessor) cleanup() {
	p.mu.Lock()
	defer p.mu.Unlock()

	now := time.Now()
	for key, entry := range p.flows {
		// Remove flows older than 10 minutes
		if now.Sub(entry.LastSeen) > 10*time.Minute {
			delete(p.flows, key)
		}
	}
}

// Stats returns processor statistics
func (p *NDPIProcessor) Stats() (packets, flows uint64) {
	return atomic.LoadUint64(&p.packets), atomic.LoadUint64(&p.flowsDetected)
}
