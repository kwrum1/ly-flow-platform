package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"strings"
	"sync"
	"time"
)

var errRASPBridgeToken = errors.New("RASP bridge token invalid")

type raspBridgeTokenSet struct {
	mu            sync.RWMutex
	current       string
	previous      string
	previousUntil time.Time
	overlap       time.Duration
	now           func() time.Time
}

func newRASPBridgeTokenSet(current string, overlap time.Duration, now func() time.Time) (*raspBridgeTokenSet, error) {
	current = strings.TrimSpace(current)
	if current == "" || overlap <= 0 || now == nil {
		return nil, errRASPBridgeToken
	}
	return &raspBridgeTokenSet{current: current, overlap: overlap, now: now}, nil
}

func (tokens *raspBridgeTokenSet) Authenticate(candidate string) bool {
	tokens.mu.RLock()
	defer tokens.mu.RUnlock()
	if secureRASPBridgeTokenEqual(candidate, tokens.current) {
		return true
	}
	return tokens.now().Before(tokens.previousUntil) && secureRASPBridgeTokenEqual(candidate, tokens.previous)
}

func (tokens *raspBridgeTokenSet) Rotate(next string) error {
	next = strings.TrimSpace(next)
	if next == "" {
		return errRASPBridgeToken
	}
	tokens.mu.Lock()
	defer tokens.mu.Unlock()
	if secureRASPBridgeTokenEqual(next, tokens.current) {
		return errRASPBridgeToken
	}
	tokens.previous = tokens.current
	tokens.previousUntil = tokens.now().Add(tokens.overlap)
	tokens.current = next
	return nil
}

func (tokens *raspBridgeTokenSet) Current() string {
	tokens.mu.RLock()
	defer tokens.mu.RUnlock()
	return tokens.current
}

func generateRASPBridgeToken() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func secureRASPBridgeTokenEqual(left, right string) bool {
	if strings.TrimSpace(left) == "" || strings.TrimSpace(right) == "" {
		return false
	}
	leftDigest := sha256.Sum256([]byte(left))
	rightDigest := sha256.Sum256([]byte(right))
	return subtle.ConstantTimeCompare(leftDigest[:], rightDigest[:]) == 1
}
