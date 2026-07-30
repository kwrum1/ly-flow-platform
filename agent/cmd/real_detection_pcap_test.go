package main

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

func TestGenerateRealDetectionPCAP(t *testing.T) {
	output := os.Getenv("SURICATA_REAL_DETECTION_PCAP_OUTPUT")
	if output == "" {
		output = filepath.Join(t.TempDir(), "real-detections.pcap")
	}
	file, err := os.Create(output)
	if err != nil {
		t.Fatalf("create PCAP: %v", err)
	}
	writer := pcapgo.NewWriter(file)
	if err := writer.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		_ = file.Close()
		t.Fatalf("write PCAP header: %v", err)
	}
	clock := packetClock{writer: writer, next: time.Date(2026, time.July, 23, 0, 0, 0, 0, time.UTC)}
	conversations := []tcpConversation{
		{clientIP: "10.0.0.21", serverIP: "203.0.113.21", clientPort: 54001, serverPort: 80, request: []byte("GET / HTTP/1.1\r\nHost: et.example\r\nUser-Agent: Poller\r\nConnection: close\r\n\r\n"), response: []byte("HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")},
		{clientIP: "10.0.0.22", serverIP: "203.0.113.22", clientPort: 54002, serverPort: 80, request: []byte("GET /debian HTTP/1.1\r\nHost: debian.org\r\nUser-Agent: Debian APT\r\nConnection: close\r\n\r\n"), response: []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")},
		{clientIP: "10.0.0.23", serverIP: "203.0.113.23", clientPort: 54003, serverPort: 4444, request: []byte("PCRatd"), response: []byte("OK")},
		{clientIP: "203.0.113.24", serverIP: "10.0.0.24", clientPort: 54004, serverPort: 953, request: []byte("_authAAAA_ctrl_ser_tim_exp"), response: []byte("OK")},
	}
	for _, conversation := range conversations {
		if err := writeTCP(&clock, conversation); err != nil {
			_ = file.Close()
			t.Fatalf("write conversation: %v", err)
		}
	}
	if err := file.Close(); err != nil {
		t.Fatalf("close PCAP: %v", err)
	}
	info, err := os.Stat(output)
	if err != nil || info.Size() == 0 {
		t.Fatalf("generated PCAP is empty: info=%v err=%v", info, err)
	}
	fmt.Printf("real_detection_pcap=%s bytes=%d\n", output, info.Size())
}
