package main

import (
	"net"
	"strings"
)

// suricataSourceAttribution resolves the real client when an HTTP alert was
// observed on a trusted reverse proxy. The returned clientIP is what the UI
// should show as the event source; proxyIP preserves the packet source for
// traceability and the attribution record is stored in raw_event.
func suricataSourceAttribution(event map[string]interface{}, trustedCIDRs []*net.IPNet) (clientIP, proxyIP string, attribution *SourceAttribution) {
	proxyIP = strings.TrimSpace(asString(event["src_ip"]))
	clientIP = proxyIP
	http := asMap(event["http"])
	if len(http) == 0 {
		return clientIP, proxyIP, nil
	}
	xff := strings.TrimSpace(asString(http["xff"]))
	if xff == "" {
		return clientIP, proxyIP, nil
	}
	attribution = resolveSourceAttribution(proxyIP, xff, trustedCIDRs)
	if attribution != nil && strings.TrimSpace(attribution.ClientIP) != "" {
		clientIP = attribution.ClientIP
	}
	return clientIP, proxyIP, attribution
}
