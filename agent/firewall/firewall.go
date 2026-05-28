package firewall

import (
	"fmt"
	"net"
	"time"
)

type Backend string

const (
	BackendNFTables  Backend = "nftables"
	BackendIPTables  Backend = "iptables"
	BackendFirewalld Backend = "firewalld"
	BackendNoop      Backend = "noop"
)

type BlockRequest struct {
	IP        string
	Reason    string
	TTL       time.Duration
	Temporary bool
}

type Whitelist struct {
	CIDRs []string
}

func (w Whitelist) AllowsBlock(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, cidr := range w.CIDRs {
		_, network, err := net.ParseCIDR(cidr)
		if err == nil && network.Contains(parsed) {
			return false
		}
	}
	return true
}

func ValidateBlock(req BlockRequest, whitelist Whitelist) error {
	if net.ParseIP(req.IP) == nil {
		return fmt.Errorf("invalid ip")
	}
	if !whitelist.AllowsBlock(req.IP) {
		return fmt.Errorf("ip is whitelisted")
	}
	if req.Temporary && req.TTL <= 0 {
		return fmt.Errorf("temporary block requires ttl")
	}
	return nil
}
