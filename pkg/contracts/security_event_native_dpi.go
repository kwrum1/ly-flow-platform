package contracts

import (
	"fmt"
	"strconv"
	"time"
)

type nativeDPIAlert struct {
	ID        uint64 `json:"id"`
	Timestamp string `json:"timestamp"`
	Type      string `json:"type"`
	SrcIP     string `json:"src_ip"`
	DstIP     string `json:"dst_ip"`
	SrcPort   uint16 `json:"src_port"`
	DstPort   uint16 `json:"dst_port"`
	Protocol  string `json:"protocol"`
	Signature string `json:"signature"`
	Category  string `json:"category"`
	Severity  uint8  `json:"severity"`
	Score     int    `json:"score"`
	Status    string `json:"status"`
	SensorID  string `json:"sensor_id"`
	Domain    string `json:"domain,omitempty"`
	Data      string `json:"data,omitempty"`
}

func decodeNativeDPIAlert(schema string, data []byte) (normalizedSourceRecord, string, string, error) {
	var alert nativeDPIAlert
	if err := decodeExpectedNative(schema, NativeDPIAlert, data, &alert); err != nil {
		return normalizedSourceRecord{}, "", "", err
	}
	occurredAt, err := time.Parse(time.RFC3339Nano, alert.Timestamp)
	if err != nil {
		return normalizedSourceRecord{}, "", "", fmt.Errorf("parse DPI timestamp: %w", err)
	}
	return nativeRecord(strconv.FormatUint(alert.ID, 10), alert.SensorID, alert.Type, occurredAt, dpiAlertSeverity(alert.Severity), data, "", ""), "contracts.dpiAlertAdapter", schema, nil
}

func dpiAlertSeverity(value uint8) AlertSeverity {
	switch value {
	case 1:
		return SeverityCritical
	case 2:
		return SeverityHigh
	case 3:
		return SeverityMedium
	default:
		return SeverityLow
	}
}
