package incidentlifecycle

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"strconv"
	"time"
)

func CommandPayloadHash(command Command) string {
	values := []string{
		command.IncidentID,
		string(command.Action),
		command.Actor.ID,
		string(command.Actor.Role),
		string(command.To),
		command.Assignee,
		command.Reason,
		canonicalCommandTime(command.SuppressUntil),
		strconv.FormatInt(command.ExpectedVersion, 10),
	}
	var length [8]byte
	canonical := make([]byte, 0, 256)
	for _, value := range values {
		binary.BigEndian.PutUint64(length[:], uint64(len(value)))
		canonical = append(canonical, length[:]...)
		canonical = append(canonical, value...)
	}
	digest := sha256.Sum256(canonical)
	return hex.EncodeToString(digest[:])
}

func canonicalCommandTime(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.UTC().Format(time.RFC3339Nano)
}
