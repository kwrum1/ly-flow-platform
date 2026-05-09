package aggregator

import (
	"crypto/sha256"
	"encoding/hex"
	"ly-flow-platform/pkg/model"
)

// AlertFingerprint 生成告警指纹
// 生成规则：category + severity + src_ip + domain 组合
func AlertFingerprint(alert *model.Alert) string {
	data := alert.Category +
		string(rune(alert.Severity)) +
		alert.SrcIP +
		alert.Domain

	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:8])
}
