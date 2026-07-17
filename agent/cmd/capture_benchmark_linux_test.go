//go:build linux

package main

import (
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

type syntheticCaptureProfile struct {
	SchemaVersion    string `json:"schema_version"`
	Name             string `json:"name"`
	Inert            bool   `json:"inert"`
	Packets          int    `json:"packets"`
	MaxPacketsPerCPU int    `json:"max_packets_per_cpu"`
	SourceIP         string `json:"source_ip"`
	DestinationIP    string `json:"destination_ip"`
	SourcePort       uint16 `json:"source_port"`
	DestinationPort  uint16 `json:"destination_port"`
}

func TestLinuxSyntheticPCAPProfileReportsBoundedLossAndCPU(t *testing.T) {
	// Given
	profileData, err := os.ReadFile(filepath.Join("testdata", "capture-quality", "inert-synthetic-profile.json"))
	if err != nil {
		t.Fatalf("read profile: %v", err)
	}
	var profile syntheticCaptureProfile
	if err := json.Unmarshal(profileData, &profile); err != nil {
		t.Fatalf("parse profile: %v", err)
	}
	if profile.SchemaVersion != "lyflow.capture-benchmark.v1" || !profile.Inert || profile.Packets <= 0 || profile.MaxPacketsPerCPU <= 0 {
		t.Fatalf("unsafe or malformed profile: %#v", profile)
	}
	packetLimit := min(profile.Packets, max(1, runtime.NumCPU())*profile.MaxPacketsPerCPU)
	pcapPath := filepath.Join(t.TempDir(), "inert.pcap")
	pcapFile, err := os.Create(pcapPath)
	if err != nil {
		t.Fatalf("create pcap: %v", err)
	}
	writer := pcapgo.NewWriter(pcapFile)
	if err := writer.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		t.Fatalf("write pcap header: %v", err)
	}
	buffer := gopacket.NewSerializeBuffer()
	ipv4 := &layers.IPv4{Version: 4, TTL: 64, SrcIP: net.ParseIP(profile.SourceIP), DstIP: net.ParseIP(profile.DestinationIP), Protocol: layers.IPProtocolTCP}
	tcp := &layers.TCP{SrcPort: layers.TCPPort(profile.SourcePort), DstPort: layers.TCPPort(profile.DestinationPort), SYN: true, Seq: 1, Window: 64240}
	if err := tcp.SetNetworkLayerForChecksum(ipv4); err != nil {
		t.Fatalf("set TCP checksum network layer: %v", err)
	}
	err = gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
		&layers.Ethernet{SrcMAC: net.HardwareAddr{0x02, 0, 0, 0, 0, 1}, DstMAC: net.HardwareAddr{0x02, 0, 0, 0, 0, 2}, EthernetType: layers.EthernetTypeIPv4},
		ipv4, tcp)
	if err != nil {
		t.Fatalf("serialize packet: %v", err)
	}
	data := buffer.Bytes()
	for index := 0; index < packetLimit; index++ {
		captureInfo := gopacket.CaptureInfo{Timestamp: time.Unix(1700000000, int64(index)*1000).UTC(), CaptureLength: len(data), Length: len(data)}
		if err := writer.WritePacket(captureInfo, data); err != nil {
			t.Fatalf("write packet: %v", err)
		}
	}
	if err := pcapFile.Close(); err != nil {
		t.Fatalf("close pcap: %v", err)
	}
	file, err := os.Open(pcapPath)
	if err != nil {
		t.Fatalf("open pcap: %v", err)
	}
	defer file.Close()
	reader, err := pcapgo.NewReader(file)
	if err != nil {
		t.Fatalf("open pcap reader: %v", err)
	}
	agent := NewAgent(&Config{TrafficInterface: "synthetic0"})
	wallStarted := time.Now()
	cpuStarted := processCPUTime(t)
	parsed, parserDrops := 0, 0

	// When
	for {
		data, _, err := reader.ReadPacketData()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("read packet: %v", err)
		}
		packet := gopacket.NewPacket(data, layers.LinkTypeEthernet, gopacket.DecodeOptions{Lazy: true, NoCopy: true})
		if agent.observationFromPacket(packet, len(data), "synthetic_pcap").Protocol == "" {
			parserDrops++
		} else {
			parsed++
		}
	}
	cpuUsed := processCPUTime(t) - cpuStarted
	wallUsed := time.Since(wallStarted)
	cpuPercent := 0.0
	if wallUsed > 0 {
		cpuPercent = float64(cpuUsed) / float64(wallUsed) * 100
	}
	lossPercent := float64(parserDrops) / float64(packetLimit) * 100

	// Then
	if parsed+parserDrops != packetLimit || packetLimit > max(1, runtime.NumCPU())*profile.MaxPacketsPerCPU {
		t.Fatalf("benchmark escaped hardware bound: parsed=%d drops=%d limit=%d", parsed, parserDrops, packetLimit)
	}
	if cpuPercent > float64(max(1, runtime.NumCPU()))*100+1 {
		t.Fatalf("CPU report exceeds available hardware: %.2f", cpuPercent)
	}
	t.Logf("capture_benchmark profile=%s packets=%d parser_packet_loss_percent=%.4f kernel_packet_loss=not_measured cpu_seconds=%.6f cpu_percent=%.2f local_cpus=%d visibility_claim=offline_parser_only", profile.Name, packetLimit, lossPercent, cpuUsed.Seconds(), cpuPercent, runtime.NumCPU())
}

func processCPUTime(t *testing.T) time.Duration {
	t.Helper()
	var usage syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &usage); err != nil {
		t.Fatalf("get process CPU: %v", err)
	}
	return timevalDuration(usage.Utime) + timevalDuration(usage.Stime)
}

func timevalDuration(value syscall.Timeval) time.Duration {
	return time.Duration(value.Sec)*time.Second + time.Duration(value.Usec)*time.Microsecond
}
