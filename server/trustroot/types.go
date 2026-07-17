package trustroot

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
)

var (
	ErrBundleSelfTrust  = errors.New("trustroot: release root must be external to bundle")
	ErrMalformedRoot    = errors.New("trustroot: malformed public root")
	ErrRoleOffline      = errors.New("trustroot: role has no online signer")
	ErrRootRevoked      = errors.New("trustroot: root revoked")
	ErrSignature        = errors.New("trustroot: signature verification failed")
	ErrIncompleteLayout = errors.New("trustroot: online root layout incomplete")
)

type RootRole string

const (
	PolicyRoot  RootRole = "policy"
	AuditRoot   RootRole = "audit"
	RuleRoot    RootRole = "rule"
	ReleaseRoot RootRole = "release"
)

type KeyRole string

const (
	PolicySigner KeyRole = "policy"
	AuditSigner  KeyRole = "audit"
	RuleSigner   KeyRole = "rule"
)

func (r RootRole) OnlineKeyRole() (KeyRole, error) {
	switch r {
	case PolicyRoot:
		return PolicySigner, nil
	case AuditRoot:
		return AuditSigner, nil
	case RuleRoot:
		return RuleSigner, nil
	case ReleaseRoot:
		return "", ErrRoleOffline
	default:
		return "", ErrMalformedRoot
	}
}

type Signer struct {
	privateKey ed25519.PrivateKey
}

func (s Signer) Valid() bool {
	return len(s.privateKey) == ed25519.PrivateKeySize
}

func (s Signer) Sign(payload []byte) []byte {
	return ed25519.Sign(s.privateKey, payload)
}

func (s Signer) Fingerprint() string {
	publicKey := s.privateKey.Public().(ed25519.PublicKey)
	return fingerprint(publicKey)
}

func fingerprint(publicKey ed25519.PublicKey) string {
	digest := sha256.Sum256(publicKey)
	return hex.EncodeToString(digest[:])
}
