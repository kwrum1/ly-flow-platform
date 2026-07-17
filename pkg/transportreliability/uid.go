package transportreliability

import (
	"crypto/sha256"
	"encoding/hex"
)

func DeterministicUID(sink, stream, nativeID string) string {
	sum := sha256.Sum256([]byte(sink + "\x00" + stream + "\x00" + nativeID))
	return "uid-" + hex.EncodeToString(sum[:16])
}
