package main

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

const (
	pcapFixtureSHA256 = "1020dcf67299ac65cead8ad7169039cf64af93fa8f01af877e57f479a6219022"
	tcpSYN            = 1 << iota
	tcpACK
	tcpPSH
	tcpFIN
)

type tcpConversation struct {
	clientIP   string
	serverIP   string
	clientPort uint16
	serverPort uint16
	request    []byte
	response   []byte
}

type packetClock struct {
	writer *pcapgo.Writer
	next   time.Time
}

type tcpPacket struct {
	source          net.IP
	destination     net.IP
	sourcePort      uint16
	destinationPort uint16
	sequence        uint32
	acknowledgment  uint32
	flags           byte
	payload         []byte
}

type udpPacket struct {
	source          net.IP
	destination     net.IP
	sourcePort      uint16
	destinationPort uint16
	dns             *layers.DNS
}

func TestGenerateSuricataProfilePCAP(t *testing.T) {
	output := os.Getenv("SURICATA_PCAP_OUTPUT")
	if output == "" {
		output = filepath.Join(t.TempDir(), "inert.pcap")
	}
	if err := generateSuricataProfilePCAP(output); err != nil {
		t.Fatalf("generate fixture: %v", err)
	}
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatalf("read generated fixture: %v", err)
	}
	digest := sha256.Sum256(data)
	if actual := fmt.Sprintf("%x", digest); actual != pcapFixtureSHA256 {
		t.Fatalf("generated PCAP sha256 = %s, expected %s", actual, pcapFixtureSHA256)
	}
}

func generateSuricataProfilePCAP(output string) (resultErr error) {
	file, err := os.Create(output)
	if err != nil {
		return fmt.Errorf("create PCAP: %w", err)
	}
	defer func() {
		if err := file.Close(); err != nil && resultErr == nil {
			resultErr = fmt.Errorf("close PCAP: %w", err)
		}
	}()
	writer := pcapgo.NewWriter(file)
	if err := writer.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		return fmt.Errorf("write PCAP header: %w", err)
	}
	clock := packetClock{writer: writer, next: time.Date(2026, time.July, 13, 10, 0, 0, 0, time.UTC)}
	if err := writeDNS(&clock); err != nil {
		return err
	}
	if err := writeTCP(&clock, tcpConversation{
		clientIP: "10.0.0.12", serverIP: "203.0.113.80", clientPort: 53002, serverPort: 80,
		request:  []byte("GET /fixture HTTP/1.1\r\nHost: profile.test\r\nUser-Agent: lyflow-inert-fixture\r\nConnection: close\r\n\r\n"),
		response: []byte("HTTP/1.1 200 OK\r\nContent-Length: 7\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nfixture"),
	}); err != nil {
		return err
	}
	if err := writeTCP(&clock, tcpConversation{
		clientIP: "10.0.0.13", serverIP: "203.0.113.43", clientPort: 53003, serverPort: 443,
		request: tlsClientHello(), response: tlsServerHello(),
	}); err != nil {
		return err
	}
	return nil
}

func writeDNS(clock *packetClock) error {
	client, server := net.ParseIP("10.0.0.11").To4(), net.ParseIP("203.0.113.53").To4()
	question := layers.DNSQuestion{Name: []byte("profile.test"), Type: layers.DNSTypeA, Class: layers.DNSClassIN}
	query := &layers.DNS{ID: 0x4c59, QR: false, RD: true, QDCount: 1, Questions: []layers.DNSQuestion{question}}
	if err := clock.writeUDP(udpPacket{source: client, destination: server, sourcePort: 53001, destinationPort: 53, dns: query}); err != nil {
		return fmt.Errorf("write DNS query: %w", err)
	}
	answer := layers.DNSResourceRecord{Name: []byte("profile.test"), Type: layers.DNSTypeA, Class: layers.DNSClassIN, TTL: 60, IP: net.ParseIP("198.51.100.7").To4()}
	response := &layers.DNS{ID: 0x4c59, QR: true, AA: true, RA: true, QDCount: 1, ANCount: 1, Questions: []layers.DNSQuestion{question}, Answers: []layers.DNSResourceRecord{answer}}
	if err := clock.writeUDP(udpPacket{source: server, destination: client, sourcePort: 53, destinationPort: 53001, dns: response}); err != nil {
		return fmt.Errorf("write DNS response: %w", err)
	}
	return nil
}

func writeTCP(clock *packetClock, conversation tcpConversation) error {
	client, server := net.ParseIP(conversation.clientIP).To4(), net.ParseIP(conversation.serverIP).To4()
	if err := clock.writeTCP(tcpPacket{source: client, destination: server, sourcePort: conversation.clientPort, destinationPort: conversation.serverPort, sequence: 1000, flags: tcpSYN}); err != nil {
		return fmt.Errorf("write TCP SYN: %w", err)
	}
	if err := clock.writeTCP(tcpPacket{source: server, destination: client, sourcePort: conversation.serverPort, destinationPort: conversation.clientPort, sequence: 2000, acknowledgment: 1001, flags: tcpSYN | tcpACK}); err != nil {
		return fmt.Errorf("write TCP SYN-ACK: %w", err)
	}
	if err := clock.writeTCP(tcpPacket{source: client, destination: server, sourcePort: conversation.clientPort, destinationPort: conversation.serverPort, sequence: 1001, acknowledgment: 2001, flags: tcpACK}); err != nil {
		return fmt.Errorf("write TCP ACK: %w", err)
	}
	if err := clock.writeTCP(tcpPacket{source: client, destination: server, sourcePort: conversation.clientPort, destinationPort: conversation.serverPort, sequence: 1001, acknowledgment: 2001, flags: tcpPSH | tcpACK, payload: conversation.request}); err != nil {
		return fmt.Errorf("write TCP request: %w", err)
	}
	clientEnd := uint32(1001 + len(conversation.request))
	serverEnd := uint32(2001 + len(conversation.response))
	if err := clock.writeTCP(tcpPacket{source: server, destination: client, sourcePort: conversation.serverPort, destinationPort: conversation.clientPort, sequence: 2001, acknowledgment: clientEnd, flags: tcpPSH | tcpACK, payload: conversation.response}); err != nil {
		return fmt.Errorf("write TCP response: %w", err)
	}
	if err := clock.writeTCP(tcpPacket{source: client, destination: server, sourcePort: conversation.clientPort, destinationPort: conversation.serverPort, sequence: clientEnd, acknowledgment: serverEnd, flags: tcpACK}); err != nil {
		return fmt.Errorf("write TCP response ACK: %w", err)
	}
	if err := clock.writeTCP(tcpPacket{source: client, destination: server, sourcePort: conversation.clientPort, destinationPort: conversation.serverPort, sequence: clientEnd, acknowledgment: serverEnd, flags: tcpFIN | tcpACK}); err != nil {
		return fmt.Errorf("write TCP FIN: %w", err)
	}
	if err := clock.writeTCP(tcpPacket{source: server, destination: client, sourcePort: conversation.serverPort, destinationPort: conversation.clientPort, sequence: serverEnd, acknowledgment: clientEnd + 1, flags: tcpFIN | tcpACK}); err != nil {
		return fmt.Errorf("write TCP FIN-ACK: %w", err)
	}
	return clock.writeTCP(tcpPacket{source: client, destination: server, sourcePort: conversation.clientPort, destinationPort: conversation.serverPort, sequence: clientEnd + 1, acknowledgment: serverEnd + 1, flags: tcpACK})
}

func (clock *packetClock) writeUDP(packet udpPacket) error {
	udp := &layers.UDP{SrcPort: layers.UDPPort(packet.sourcePort), DstPort: layers.UDPPort(packet.destinationPort)}
	ip := &layers.IPv4{SrcIP: packet.source, DstIP: packet.destination, Version: 4, TTL: 64, Protocol: layers.IPProtocolUDP}
	udp.SetNetworkLayerForChecksum(ip)
	return clock.write([]gopacket.SerializableLayer{ethernet(packet.source), ip, udp, packet.dns})
}

func (clock *packetClock) writeTCP(packet tcpPacket) error {
	tcp := &layers.TCP{SrcPort: layers.TCPPort(packet.sourcePort), DstPort: layers.TCPPort(packet.destinationPort), Seq: packet.sequence, Ack: packet.acknowledgment, SYN: packet.flags&tcpSYN != 0, ACK: packet.flags&tcpACK != 0, PSH: packet.flags&tcpPSH != 0, FIN: packet.flags&tcpFIN != 0, Window: 65535}
	ip := &layers.IPv4{SrcIP: packet.source, DstIP: packet.destination, Version: 4, TTL: 64, Protocol: layers.IPProtocolTCP}
	tcp.SetNetworkLayerForChecksum(ip)
	layersToWrite := []gopacket.SerializableLayer{ethernet(packet.source), ip, tcp}
	if len(packet.payload) > 0 {
		layersToWrite = append(layersToWrite, gopacket.Payload(packet.payload))
	}
	return clock.write(layersToWrite)
}

func (clock *packetClock) write(packetLayers []gopacket.SerializableLayer) error {
	buffer := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, packetLayers...); err != nil {
		return err
	}
	data := buffer.Bytes()
	if err := clock.writer.WritePacket(gopacket.CaptureInfo{Timestamp: clock.next, CaptureLength: len(data), Length: len(data)}, data); err != nil {
		return err
	}
	clock.next = clock.next.Add(100 * time.Millisecond)
	return nil
}

func tlsClientHello() []byte {
	name := []byte("profile.test")
	sni := append([]byte{0, byte(len(name) + 3), 0, 0, byte(len(name))}, name...)
	extensions := append(tlsExtension(0, sni), tlsExtension(43, []byte{2, 3, 4})...)
	body := append([]byte{3, 3}, bytes.Repeat([]byte{0x11}, 32)...)
	body = append(body, 0, 0, 2, 0x13, 0x01, 1, 0, byte(len(extensions)>>8), byte(len(extensions)))
	body = append(body, extensions...)
	return tlsRecord(1, body)
}

func tlsServerHello() []byte {
	extensions := tlsExtension(43, []byte{3, 4})
	body := append([]byte{3, 3}, bytes.Repeat([]byte{0x22}, 32)...)
	body = append(body, 0, 0x13, 1, 0, byte(len(extensions)>>8), byte(len(extensions)))
	body = append(body, extensions...)
	return tlsRecord(2, body)
}

func tlsExtension(kind byte, data []byte) []byte {
	return append([]byte{0, kind, byte(len(data) >> 8), byte(len(data))}, data...)
}

func tlsRecord(kind byte, body []byte) []byte {
	handshake := append([]byte{kind, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
	return append([]byte{22, 3, 1, byte(len(handshake) >> 8), byte(len(handshake))}, handshake...)
}

func ethernet(source net.IP) *layers.Ethernet {
	client := net.HardwareAddr{2, 0, 0, 0, 0, 1}
	server := net.HardwareAddr{2, 0, 0, 0, 0, 2}
	if source[0] == 10 {
		return &layers.Ethernet{SrcMAC: client, DstMAC: server, EthernetType: layers.EthernetTypeIPv4}
	}
	return &layers.Ethernet{SrcMAC: server, DstMAC: client, EthernetType: layers.EthernetTypeIPv4}
}
