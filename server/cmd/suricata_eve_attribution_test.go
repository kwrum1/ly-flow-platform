package main

import (
	"net"
	"testing"

	"github.com/lyflow/ly-flow-platform/server/xdr/testdata"
)

func testCIDRs(t *testing.T, values []string) []*net.IPNet {
	t.Helper()
	out := make([]*net.IPNet, 0, len(values))
	for _, cidr := range values {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			t.Fatalf("invalid test CIDR %s: %v", cidr, err)
		}
		out = append(out, network)
	}
	return out
}

func TestSuricataSourceAttribution(t *testing.T) {
	cases := append([]struct {
		Name         string
		RemoteAddr   string
		XFF          string
		TrustedCIDRs []string
		Expected     string
	}{}, testdata.TrustedProxyXFFCases...)
	cases = append(cases, struct {
		Name         string
		RemoteAddr   string
		XFF          string
		TrustedCIDRs []string
		Expected     string
	}{
		Name: "lyflow-reverse-proxy", RemoteAddr: "10.1.18.252",
		XFF: "112.91.91.10", TrustedCIDRs: []string{"10.1.18.251/32", "10.1.18.252/32"},
		Expected: "112.91.91.10",
	})
	for _, tc := range cases {
		t.Run(tc.Name, func(t *testing.T) {
			event := map[string]interface{}{
				"src_ip": tc.RemoteAddr,
				"http":   map[string]interface{}{"xff": tc.XFF},
			}
			client, proxy, attr := suricataSourceAttribution(event, testCIDRs(t, tc.TrustedCIDRs))
			if client != tc.Expected {
				t.Fatalf("client IP: want %s, got %s", tc.Expected, client)
			}
			if proxy != tc.RemoteAddr {
				t.Fatalf("proxy IP: want %s, got %s", tc.RemoteAddr, proxy)
			}
			if tc.XFF != "" && attr == nil {
				t.Fatal("expected attribution record")
			}
		})
	}
}

func TestSuricataSourceAttributionWithoutHTTP(t *testing.T) {
	event := map[string]interface{}{"src_ip": "10.1.18.252"}
	client, proxy, attr := suricataSourceAttribution(event, nil)
	if client != "10.1.18.252" || proxy != "10.1.18.252" || attr != nil {
		t.Fatalf("unexpected non-HTTP attribution: client=%s proxy=%s attr=%+v", client, proxy, attr)
	}
}
