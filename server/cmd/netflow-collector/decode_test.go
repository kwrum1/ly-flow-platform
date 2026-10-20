package main

import (
	"encoding/binary"
	"testing"
	"time"
)

func appendU16(buf []byte, value uint16) []byte {
	return append(buf, byte(value>>8), byte(value))
}

func appendU32(buf []byte, value uint32) []byte {
	return append(buf, byte(value>>24), byte(value>>16), byte(value>>8), byte(value))
}

func netflowHeader() []byte {
	header := make([]byte, 20)
	binary.BigEndian.PutUint16(header[0:2], 9)
	binary.BigEndian.PutUint16(header[2:4], 2)
	binary.BigEndian.PutUint32(header[4:8], 1000)
	binary.BigEndian.PutUint32(header[8:12], uint32(time.Now().Unix()))
	binary.BigEndian.PutUint32(header[12:16], 1)
	return header
}

func lyprobeTemplateSet() []byte {
	body := make([]byte, 0, 36)
	body = appendU16(body, 0x0101)
	body = appendU16(body, 8)
	fields := [][2]uint16{
		{4, 1},      // protocol
		{8, 4},      // IPv4 source
		{12, 4},     // IPv4 destination
		{7, 2},      // source port
		{11, 2},     // destination port
		{57705, 32}, // threat type
		{57706, 32}, // threat name
		{57707, 16}, // threat version
	}
	for _, field := range fields {
		body = appendU16(body, field[0])
		body = appendU16(body, field[1])
	}
	set := appendU16(nil, 0)
	set = appendU16(set, uint16(len(body)+4))
	return append(set, body...)
}

func lyprobeDataRecord() []byte {
	record := []byte{6, 10, 1, 18, 100, 10, 1, 18, 126}
	record = appendU16(record, 43210)
	record = appendU16(record, 443)
	threatType := make([]byte, 32)
	copy(threatType, "MALWARE")
	record = append(record, threatType...)
	threatName := make([]byte, 32)
	copy(threatName, "lyprobe-test-signature")
	record = append(record, threatName...)
	threatVersion := make([]byte, 16)
	copy(threatVersion, "2026.10")
	return append(record, threatVersion...)
}

func TestDecodeV9LyprobeThreatFields(t *testing.T) {
	templates := map[string]Template{}
	packet := append(netflowHeader(), lyprobeTemplateSet()...)
	if _, err := DecodeV9(packet, templates, "127.0.0.1"); err != nil {
		t.Fatalf("template decode: %v", err)
	}
	if _, ok := templates[templateKey("127.0.0.1", 0x0101)]; !ok {
		t.Fatalf("template 0x0101 was not cached: %#v", templates)
	}

	data := appendU16(nil, 0x0101)
	data = appendU16(data, uint16(len(lyprobeDataRecord())+4))
	data = append(data, lyprobeDataRecord()...)
	packet = append(netflowHeader(), data...)
	records, err := DecodeV9(packet, templates, "127.0.0.1")
	if err != nil {
		t.Fatalf("data decode: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("records = %d, want 1", len(records))
	}
	record := records[0]
	if record["src_ip"] != "10.1.18.100" || record["dst_ip"] != "10.1.18.126" {
		t.Fatalf("unexpected addresses: %#v", record)
	}
	if record["src_port"] != int64(43210) || record["dst_port"] != int64(443) {
		t.Fatalf("unexpected ports: %#v", record)
	}
	if record["threat_type"] != "MALWARE" || record["threat_name"] != "lyprobe-test-signature" {
		t.Fatalf("unexpected threat fields: %#v", record)
	}
}

func TestDecodeV9RejectsUnspecifiedAddresses(t *testing.T) {
	templates := map[string]Template{}
	packet := append(netflowHeader(), lyprobeTemplateSet()...)
	if _, err := DecodeV9(packet, templates, "127.0.0.1"); err != nil {
		t.Fatalf("template decode: %v", err)
	}
	record := lyprobeDataRecord()
	copy(record[1:5], []byte{0, 0, 0, 0})
	copy(record[5:9], []byte{0, 0, 0, 0})
	data := appendU16(nil, 0x0101)
	data = appendU16(data, uint16(len(record)+4))
	data = append(data, record...)
	packet = append(netflowHeader(), data...)
	records, err := DecodeV9(packet, templates, "127.0.0.1")
	if err != nil {
		t.Fatalf("data decode: %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("records = %d, want 0 for unspecified addresses", len(records))
	}
}

	if _, err := DecodeV9(make([]byte, 20), nil, "127.0.0.1"); err == nil {
		t.Fatal("expected non-v9 payload to be rejected")
	}
}
