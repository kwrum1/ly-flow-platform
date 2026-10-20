package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"time"
)

// DecodeV9 decodes the subset of NetFlow v9 used by lyprobe: template flowset
// 0 plus data flowsets. Templates are cached per exporter IP because NetFlow
// v9 is stateful and templates may be sent in an earlier datagram.
func DecodeV9(packet []byte, templates map[string]Template, source string) ([]Record, error) {
	if len(packet) < 20 {
		return nil, fmt.Errorf("packet too short")
	}
	if binary.BigEndian.Uint16(packet[0:2]) != 9 {
		return nil, fmt.Errorf("not NetFlow v9")
	}
	unixSecs := binary.BigEndian.Uint32(packet[8:12])
	occurred := time.Unix(int64(unixSecs), 0).UTC()
	if unixSecs == 0 {
		occurred = time.Now().UTC()
	}
	records := make([]Record, 0, 8)
	for offset := 20; offset+4 <= len(packet); {
		setID := binary.BigEndian.Uint16(packet[offset : offset+2])
		length := int(binary.BigEndian.Uint16(packet[offset+2 : offset+4]))
		if length < 4 || offset+length > len(packet) {
			break
		}
		body := packet[offset+4 : offset+length]
		switch setID {
		case 0:
			parseTemplates(body, templates, source)
		case 1:
			// Options templates are not needed for the probe flow records.
		default:
			template, ok := templates[templateKey(source, setID)]
			if !ok {
				break
			}
			recordSize := templateSize(template)
			if recordSize == 0 {
				break
			}
			for pos := 0; pos+recordSize <= len(body); pos += recordSize {
				record := decodeRecord(body[pos:pos+recordSize], template, occurred)
				if record != nil {
					records = append(records, record)
				}
			}
		}
		offset += length
	}
	return records, nil
}

func parseTemplates(body []byte, templates map[string]Template, source string) {
	for pos := 0; pos+4 <= len(body); {
		templateID := binary.BigEndian.Uint16(body[pos : pos+2])
		count := int(binary.BigEndian.Uint16(body[pos+2 : pos+4]))
		pos += 4
		fields := make([]Field, 0, count)
		for index := 0; index < count && pos+4 <= len(body); index++ {
			rawType := binary.BigEndian.Uint16(body[pos : pos+2])
			length := binary.BigEndian.Uint16(body[pos+2 : pos+4])
			pos += 4
			fieldType := rawType
			if rawType&0x8000 != 0 {
				// Enterprise field: 4-byte PEN follows the standard type/length.
				if pos+4 > len(body) {
					return
				}
				pos += 4
				fieldType = rawType &^ 0x8000
			}
			fields = append(fields, Field{Type: fieldType, Length: length})
		}
		if templateID != 0 && len(fields) > 0 {
			templates[templateKey(source, templateID)] = Template{ID: templateID, Fields: fields}
		}
	}
}

func templateKey(source string, id uint16) string {
	return source + ":" + fmt.Sprint(id)
}

func templateSize(template Template) int {
	size := 0
	for _, field := range template.Fields {
		size += int(field.Length)
	}
	return size
}

func decodeRecord(raw []byte, template Template, occurred time.Time) Record {
	record := Record{"timestamp": occurred.Format(time.RFC3339)}
	offset := 0
	for _, field := range template.Fields {
		end := offset + int(field.Length)
		if end > len(raw) {
			return nil
		}
		value := raw[offset:end]
		offset = end
		switch field.Type {
		case 1:
			record["bytes"] = uintValue(value)
		case 2:
			record["packets"] = uintValue(value)
		case 4:
			record["protocol"] = uintValue(value)
		case 7:
			record["src_port"] = uintValue(value)
		case 11:
			record["dst_port"] = uintValue(value)
		case 8:
			record["src_ip"] = ipValue(value)
		case 12:
			record["dst_ip"] = ipValue(value)
		case 57705:
			record["threat_type"] = stringValueBytes(value)
		case 57706:
			record["threat_name"] = stringValueBytes(value)
		case 57707:
			record["threat_version"] = stringValueBytes(value)
		}
	}
	if record["src_ip"] == nil || record["dst_ip"] == nil {
		return nil
	}
	digest := sha256.Sum256(append(append([]byte{}, raw...), []byte(occurred.Format(time.RFC3339Nano))...))
	record["id"] = hex.EncodeToString(digest[:8])
	return record
}

func uintValue(value []byte) int64 {
	switch len(value) {
	case 1:
		return int64(value[0])
	case 2:
		return int64(binary.BigEndian.Uint16(value))
	case 4:
		return int64(binary.BigEndian.Uint32(value))
	case 8:
		return int64(binary.BigEndian.Uint64(value))
	default:
		return 0
	}
}

func ipValue(value []byte) string {
	switch len(value) {
	case 4, 16:
		return net.IP(value).String()
	default:
		return ""
	}
}

func stringValueBytes(value []byte) string {
	return strings.TrimRight(string(value), "\x00 ")
}
