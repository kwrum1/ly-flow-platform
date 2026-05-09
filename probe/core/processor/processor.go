package processor

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"ly-flow-platform/probe/pkg/model"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/uuid"
)

// PacketInfo contains parsed packet information
type PacketInfo struct {
	SrcIP     string
	DstIP     string
	SrcPort   uint16
	DstPort   uint16
	Protocol  string
	Payload   []byte
	Timestamp time.Time
	Length    int
}

// Protocol application layer protocols
const (
	ProtoUnknown  = "UNKNOWN"
	ProtoHTTP     = "HTTP"
	ProtoHTTPS    = "HTTPS"
	ProtoDNS      = "DNS"
	ProtoTLS      = "TLS"
	ProtoSSH      = "SSH"
	ProtoFTP      = "FTP"
	ProtoSMTP     = "SMTP"
	ProtoTCP      = "TCP"
	ProtoUDP      = "UDP"
	ProtoICMP     = "ICMP"
	ProtoRaw      = "RAW"
)

// Processor handles packet processing and protocol parsing
type Processor struct {
	sensorID string
	flows    map[string]*FlowState
}

// FlowState tracks ongoing flows for aggregation
type FlowState struct {
	FirstSeen  time.Time
	LastSeen   time.Time
	Packets    uint64
	BytesIn    uint64
	BytesOut   uint64
	SrcIP      string
	DstIP      string
	SrcPort    uint16
	DstPort    uint16
	Protocol   string
	AppProto   string
	DNSQuery   string
	HTTPHost   string
	TLSSNI     string
	JA3        string
}

// NewProcessor creates a new packet processor
func NewProcessor(sensorID string) *Processor {
	return &Processor{
		sensorID: sensorID,
		flows:    make(map[string]*FlowState),
	}
}

// ProcessPacket processes a raw packet and returns FlowData
func (p *Processor) ProcessPacket(data []byte) *model.FlowData {
	info, err := ParsePacket(data)
	if err != nil {
		return nil
	}

	// Build flow key
	flowKey := p.buildFlowKey(info)
	if flowKey == "" {
		return nil
	}

	// Get or create flow state
	state, exists := p.flows[flowKey]
	if !exists {
		state = &FlowState{
			FirstSeen: info.Timestamp,
			SrcIP:     info.SrcIP,
			DstIP:     info.DstIP,
			SrcPort:   info.SrcPort,
			DstPort:   info.DstPort,
			Protocol:  p.getProtocolName(info.Protocol),
		}
		p.flows[flowKey] = state
	}

	// Update flow state
	state.LastSeen = info.Timestamp
	state.Packets++
	if strings.HasPrefix(info.SrcIP, "192.168.") || strings.HasPrefix(info.SrcIP, "10.") || strings.HasPrefix(info.SrcIP, "172.") {
		state.BytesOut += uint64(info.Length)
	} else {
		state.BytesIn += uint64(info.Length)
	}

	// Parse application layer
	p.parseApplicationLayer(state, info)

	// Detect application protocol
	state.AppProto = p.detectAppProtocol(info, state)

	return p.buildFlowData(state, info)
}

func (p *Processor) buildFlowKey(info *PacketInfo) string {
	if info.SrcIP == "" || info.DstIP == "" {
		return ""
	}
	// Use 5-tuple for flow key
	direction := fmt.Sprintf("%s:%d->%s:%d", info.SrcIP, info.SrcPort, info.DstIP, info.DstPort)
	return direction
}

func (p *Processor) getProtocolName(protocol string) string {
	switch protocol {
	case "TCP":
		return ProtoTCP
	case "UDP":
		return ProtoUDP
	case "ICMP":
		return ProtoICMP
	default:
		return ProtoRaw
	}
}

func (p *Processor) detectAppProtocol(info *PacketInfo, state *FlowState) string {
	// Check port-based protocol detection first
	switch info.DstPort {
	case 80, 8080, 8000, 8888:
		return ProtoHTTP
	case 443, 8443:
		if state.TLSSNI != "" {
			return ProtoHTTPS
		}
		return ProtoTLS
	case 53:
		return ProtoDNS
	case 22:
		return ProtoSSH
	case 21:
		return ProtoFTP
	case 25, 465, 587:
		return ProtoSMTP
	}

	// Check TLS SNI
	if state.TLSSNI != "" {
		return ProtoHTTPS
	}

	// Check HTTP Host
	if state.HTTPHost != "" {
		return ProtoHTTP
	}

	// Check DNS query
	if state.DNSQuery != "" {
		return ProtoDNS
	}

	return ProtoUnknown
}

func (p *Processor) parseApplicationLayer(state *FlowState, info *PacketInfo) {
	payload := info.Payload
	if len(payload) == 0 {
		return
	}

	// DNS parsing (port 53)
	if info.DstPort == 53 || info.SrcPort == 53 {
		state.DNSQuery = p.parseDNSQuery(payload)
		return
	}

	// HTTP parsing (port 80)
	if info.DstPort == 80 || info.SrcPort == 80 {
		host := p.parseHTTPHost(payload)
		if host != "" {
			state.HTTPHost = host
		}
		return
	}

	// TLS parsing (port 443)
	if info.DstPort == 443 || info.SrcPort == 443 {
		sni, ja3 := p.parseTLSClientHello(payload)
		if sni != "" {
			state.TLSSNI = sni
		}
		if ja3 != "" {
			state.JA3 = ja3
		}
		return
	}
}

// parseDNSQuery extracts DNS query name from UDP payload
func (p *Processor) parseDNSQuery(payload []byte) string {
	// DNS header is 12 bytes minimum
	if len(payload) < 12 {
		return ""
	}

	// Skip DNS header (12 bytes)
	// Check if this is a query (QR bit = 0)
	qr := (payload[2] >> 7) & 0x01
	if qr != 0 {
		return "" // Response, skip
	}

	// Skip header and parse question section
	offset := 12
	var name strings.Builder

	for offset < len(payload) {
		length := int(payload[offset])
		if length == 0 {
			break
		}

		// Check for compression pointer
		if length >= 0xc0 {
			break
		}

		if name.Len() > 0 {
			name.WriteByte('.')
		}
		name.Write(payload[offset+1 : offset+1+length])
		offset += 1 + length
	}

	return name.String()
}

// parseHTTPHost extracts Host header from HTTP request
func (p *Processor) parseHTTPHost(payload []byte) string {
	if len(payload) < 4 {
		return ""
	}

	// Check for HTTP request
	if string(payload[:4]) != "GET " &&
		string(payload[:4]) != "POST" &&
		string(payload[:4]) != "PUT " &&
		string(payload[:4]) != "HEAD" &&
		string(payload[:4]) != "DELE" &&
		string(payload[:4]) != "OPTI" &&
		string(payload[:4]) != "CONN" &&
		string(payload[:4]) != "PATC" {
		return ""
	}

	// Look for Host: header
	payloadStr := string(payload)
	lines := strings.Split(payloadStr, "\r\n")
	for _, line := range lines {
		if strings.HasPrefix(strings.ToLower(line), "host:") {
			host := strings.TrimPrefix(line, "host:")
			host = strings.TrimSpace(host)
			// Remove port if present
			if idx := strings.Index(host, ":"); idx > 0 {
				host = host[:idx]
			}
			return host
		}
	}

	return ""
}

// parseTLSClientHello extracts SNI and JA3 from TLS ClientHello
func (p *Processor) parseTLSClientHello(payload []byte) (sni string, ja3 string) {
	if len(payload) < 5 {
		return "", ""
	}

	// Check TLS handshake (ContentType = 0x16)
	if payload[0] != 0x16 {
		return "", ""
	}

	// TLS Record Header: ContentType(1) + Version(2) + Length(2)
	offset := 5

	// Check HandshakeType (should be 0x01 for ClientHello)
	if offset >= len(payload) || payload[offset] != 0x01 {
		return "", ""
	}
	offset++

	// Skip Handshake length (3 bytes)
	if offset+3 >= len(payload) {
		return "", ""
	}
	offset += 3

	// Skip ClientHello version (2 bytes)
	offset += 2

	// Skip Random (32 bytes)
	if offset+32 >= len(payload) {
		return "", ""
	}
	offset += 32

	// Skip Session ID length (1 byte + session ID)
	if offset >= len(payload) {
		return "", ""
	}
	sessionIDLen := int(payload[offset])
	offset += 1 + sessionIDLen

	// Skip Cipher Suites length (2 bytes + suites)
	if offset+2 >= len(payload) {
		return "", ""
	}
	cipherSuitesLen := int(payload[offset])<<8 | int(payload[offset+1])
	offset += 2 + cipherSuitesLen

	// Skip Compression Methods length (1 byte + methods)
	if offset >= len(payload) {
		return "", ""
	}
	compMethodsLen := int(payload[offset])
	offset += 1 + compMethodsLen

	// Extensions length (2 bytes)
	if offset+2 >= len(payload) {
		return "", ""
	}
	extensionsLen := int(payload[offset])<<8 | int(payload[offset+1])
	offset += 2

	extensionsEnd := offset + extensionsLen

	// Build JA3 from client hello components
	ja3Builder := strings.Builder{}
	ja3Builder.WriteString(fmt.Sprintf("%d", p.getTLSVersion(payload)))

	// Collect cipher suites for JA3
	var cipherSuites []int
	ciphersOffset := offset - extensionsLen - 2 - cipherSuitesLen - 2
	if ciphersOffset >= 5 {
		cipherStart := ciphersOffset + 2
		for i := 0; i+1 < cipherSuitesLen && i < 10; i += 2 {
			if cipherStart+i+1 < len(payload) {
				cipherSuites = append(cipherSuites, int(payload[cipherStart+i])<<8|int(payload[cipherStart+i+1]))
			}
		}
	}

	// Parse extensions to find SNI
	for offset < extensionsEnd && offset+4 < len(payload) {
		extType := int(payload[offset])<<8 | int(payload[offset+1])
		extLen := int(payload[offset+2])<<8 | int(payload[offset+3])
		offset += 4

		// SNI extension type = 0x0000
		if extType == 0 {
			// Skip SNI list length (2 bytes)
			offset += 2
			// Skip SNI type (1 byte, should be 0 for hostname)
			if offset < len(payload) && payload[offset] == 0 {
				offset++
				// SNI hostname length (2 bytes)
				if offset+1 < len(payload) {
					sniLen := int(payload[offset])<<8 | int(payload[offset+1])
					offset += 2
					if offset+sniLen <= len(payload) {
						sni = string(payload[offset : offset+sniLen])
					}
				}
			}
		}

		offset += extLen
	}

	// Calculate JA3 hash if we have cipher suites
	if len(cipherSuites) > 0 {
		ja3Builder.WriteString(",")
		for i, cs := range cipherSuites {
			if i > 0 {
				ja3Builder.WriteString("-")
			}
			ja3Builder.WriteString(fmt.Sprintf("%d", cs))
		}
		hash := md5.Sum([]byte(ja3Builder.String()))
		ja3 = hex.EncodeToString(hash[:])
	}

	return sni, ja3
}

func (p *Processor) getTLSVersion(payload []byte) int {
	// TLS record version is at bytes 1-2
	if len(payload) < 3 {
		return 0
	}
	return int(payload[1])<<8 | int(payload[2])
}

func (p *Processor) buildFlowData(state *FlowState, info *PacketInfo) *model.FlowData {
	duration := uint64(state.LastSeen.Sub(state.FirstSeen).Milliseconds())
	if duration == 0 {
		duration = 1
	}

	// Determine direction
	direction := "unknown"
	if strings.HasPrefix(info.SrcIP, "192.168.") ||
		strings.HasPrefix(info.SrcIP, "10.") ||
		strings.HasPrefix(info.SrcIP, "172.") {
		direction = "egress"
	} else {
		direction = "ingress"
	}

	return &model.FlowData{
		ID:          uuid.New().String(),
		Timestamp:   state.FirstSeen.Unix(),
		SensorID:    p.sensorID,
		SrcIP:       state.SrcIP,
		DstIP:       state.DstIP,
		SrcPort:     state.SrcPort,
		DstPort:     state.DstPort,
		Protocol:    state.Protocol,
		AppProtocol: state.AppProto,
		DNSQuery:    state.DNSQuery,
		HTTPHost:    state.HTTPHost,
		TLSSNI:      state.TLSSNI,
		JA3:         state.JA3,
		BytesIn:     state.BytesIn,
		BytesOut:    state.BytesOut,
		Packets:     state.Packets,
		DurationMs:  duration,
		Direction:   direction,
	}
}

// Cleanup removes old flow states
func (p *Processor) Cleanup(maxAge time.Duration) int {
	now := time.Now()
	removed := 0
	for key, state := range p.flows {
		if now.Sub(state.LastSeen) > maxAge {
			delete(p.flows, key)
			removed++
		}
	}
	return removed
}

// ParsePacket parses raw packet data and extracts network headers
func ParsePacket(data []byte) (*PacketInfo, error) {
	if len(data) < 14 {
		return nil, fmt.Errorf("packet too short")
	}

	packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.NoCopy)
	info := &PacketInfo{
		Timestamp: time.Now(),
		Length:    len(data),
	}

	// Extract IP layer
	var ipLayer gopacket.Layer
	for _, layer := range packet.Layers() {
		if layer.LayerType() == layers.LayerTypeIPv4 || layer.LayerType() == layers.LayerTypeIPv6 {
			ipLayer = layer
			break
		}
	}

	if ipLayer != nil {
		switch v := ipLayer.(type) {
		case *layers.IPv4:
			info.SrcIP = v.SrcIP.String()
			info.DstIP = v.DstIP.String()
			info.Protocol = v.Protocol.String()
		case *layers.IPv6:
			info.SrcIP = v.SrcIP.String()
			info.DstIP = v.DstIP.String()
			info.Protocol = "IPv6"
		}

		// Extract TCP/UDP
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp, _ := tcpLayer.(*layers.TCP)
			info.SrcPort = uint16(tcp.SrcPort)
			info.DstPort = uint16(tcp.DstPort)
			info.Payload = tcp.Payload
		} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
			udp, _ := udpLayer.(*layers.UDP)
			info.SrcPort = uint16(udp.SrcPort)
			info.DstPort = uint16(udp.DstPort)
			info.Payload = udp.Payload
		}
	}

	return info, nil
}
