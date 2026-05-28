package main

import (
	"context"
	"fmt"
	"net"
	"strings"
)

func loadTrustedProxyCIDRs(config *Config) ([]*net.IPNet, error) {
	if config.DBPool == nil {
		return []*net.IPNet{}, nil
	}
	rows, err := config.DBPool.Query(context.Background(),
		`SELECT cidr FROM xdr_trusted_proxies WHERE tenant_id=$1 ORDER BY priority DESC`, config.XDRDefaultTenant)
	if err != nil {
		return nil, fmt.Errorf("query trusted proxies: %w", err)
	}
	defer rows.Close()
	var cidrs []*net.IPNet
	for rows.Next() {
		var cidr string
		if err := rows.Scan(&cidr); err != nil {
			continue
		}
		_, network, err := net.ParseCIDR(strings.TrimSpace(cidr))
		if err != nil {
			continue
		}
		cidrs = append(cidrs, network)
	}
	return cidrs, nil
}

type SourceAttribution struct {
	ClientIP     string  `json:"client_ip"`
	RemoteAddr   string  `json:"remote_addr"`
	XFFChain     []string `json:"xff_chain,omitempty"`
	Confidence   float64 `json:"confidence"`
	Reason       string  `json:"reason"`
	TrustedHops  int     `json:"trusted_hops"`
}

func resolveSourceAttribution(remoteAddr, xffHeader string, trustedCIDRs []*net.IPNet) *SourceAttribution {
	remoteIP := net.ParseIP(strings.TrimSpace(remoteAddr))
	if remoteIP == nil {
		return &SourceAttribution{
			ClientIP:   remoteAddr,
			RemoteAddr: remoteAddr,
			Confidence: 0.20,
			Reason:     "invalid_remote_address",
		}
	}

	xffIPs := parseXFFChain(xffHeader)
	if len(xffIPs) == 0 {
		return &SourceAttribution{
			ClientIP:   remoteAddr,
			RemoteAddr: remoteAddr,
			Confidence: 0.85,
			Reason:     "no_xff_header",
		}
	}

	isRemoteTrusted := ipInCIDRs(remoteIP, trustedCIDRs)
	if !isRemoteTrusted {
		return &SourceAttribution{
			ClientIP:    remoteAddr,
			RemoteAddr:  remoteAddr,
			XFFChain:    xffIPs,
			Confidence:  0.75,
			Reason:      "remote_not_trusted_xff_ignored",
			TrustedHops: 0,
		}
	}

	trustedHops := 0
	for i := len(xffIPs) - 1; i >= 0; i-- {
		hopIP := net.ParseIP(xffIPs[i])
		if hopIP == nil {
			break
		}
		if ipInCIDRs(hopIP, trustedCIDRs) {
			trustedHops++
		} else {
			remaining := xffIPs[i:]
			var xffDisplay []string
			for j := len(xffIPs) - 1; j >= 0; j-- {
				xffDisplay = append(xffDisplay, xffIPs[j])
			}
			return &SourceAttribution{
				ClientIP:    remaining[0],
				RemoteAddr:  remoteAddr,
				XFFChain:    xffDisplay,
				Confidence:  0.95,
				Reason:      "trusted_proxy_chain_resolved",
				TrustedHops: trustedHops,
			}
		}
	}

	var xffDisplay []string
	for j := len(xffIPs) - 1; j >= 0; j-- {
		xffDisplay = append(xffDisplay, xffIPs[j])
	}
	return &SourceAttribution{
		ClientIP:    xffIPs[len(xffIPs)-1],
		RemoteAddr:  remoteAddr,
		XFFChain:    xffDisplay,
		Confidence:  0.82,
		Reason:      "all_hops_trusted_client_unclear",
		TrustedHops: trustedHops,
	}
}

func parseXFFChain(xff string) []string {
	if xff == "" {
		return nil
	}
	parts := strings.Split(xff, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

func ipInCIDRs(ip net.IP, cidrs []*net.IPNet) bool {
	if ip == nil {
		return false
	}
	for _, cidr := range cidrs {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}
