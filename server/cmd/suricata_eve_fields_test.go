package main

import (
	"encoding/json"
	"testing"
)

// Real shapes taken from this deployment's EVE output. P0-4/P0-5 regressed
// because these exact members existed in the file and were dropped on ingest.
const (
	eveAlertHTTP = `{"timestamp":"2026-11-09T16:02:18.107133+0000","flow_id":741611833741618,"in_iface":"mirror0","event_type":"alert","vlan":[39],"src_ip":"10.1.1.181","src_port":40272,"dest_ip":"10.1.18.253","dest_port":80,"proto":"TCP","app_proto":"http","direction":"to_server","community_id":"1:hzLeutRPH3Xk2mYvQ8pWqZ0sJ1k=","http":{"hostname":"jjc.sru.edu.cn","url":"/chat/imController/showOrDownByurl.do?dbPath=../../../../../etc/passwd","http_method":"GET"},"alert":{"severity":1,"signature":"ET WEB_SERVER /etc/passwd Detected in URI","signature_id":2049400}}`

	eveAlertTLS = `{"timestamp":"2026-11-10T11:00:27.326575+0000","flow_id":1061176275091630,"in_iface":"mirror0","event_type":"alert","vlan":[39],"src_ip":"10.1.1.181","src_port":39392,"dest_ip":"10.1.18.253","dest_port":443,"proto":"TCP","app_proto":"tls","direction":"to_server","community_id":"1:woTLgJZJZuGEl4+3DYwxkLR/i8I=","tls":{"sni":"portal.sru.edu.cn","ja3":{"hash":"a0e2f2759c0e0d0f8e6b4d3c2a1b0f9e"},"ja4":{"hash":"t13d1516h2_8daaf6152771_02713d6af862"}},"alert":{"severity":2,"signature":"ET MALWARE Suspicious TLS SNI","signature_id":1000020}}`

	eveAlertDNSMulti = `{"timestamp":"2026-11-10T11:00:27.326575+0000","flow_id":99,"in_iface":"mirror0","event_type":"alert","src_ip":"10.3.10.62","dest_ip":"114.114.114.114","proto":"UDP","app_proto":"dns","direction":"to_server","dns":{"version":2,"type":"query","queries":[{"rrname":"upd2.sangfor.com.cn","rrtype":"A"}]},"alert":{"severity":3,"signature":"ET TROJAN Possible DGA","signature_id":1000030}}`
)

func decodeEVE(t *testing.T, payload string) map[string]interface{} {
	t.Helper()
	var event map[string]interface{}
	if err := json.Unmarshal([]byte(payload), &event); err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	return event
}

func TestSuricataEVEJoinKeys(t *testing.T) {
	t.Run("http alert", func(t *testing.T) {
		keys := suricataEVEJoinKeys(decodeEVE(t, eveAlertHTTP))
		if keys.CommunityID != "1:hzLeutRPH3Xk2mYvQ8pWqZ0sJ1k=" {
			t.Fatalf("community_id=%q", keys.CommunityID)
		}
		if keys.FlowID != 741611833741618 {
			t.Fatalf("flow_id=%d", keys.FlowID)
		}
		if keys.Sensor != "mirror0" {
			t.Fatalf("sensor=%q, want the capture interface", keys.Sensor)
		}
		if keys.VLAN != 39 {
			t.Fatalf("vlan=%d, want 39 from the vlan array", keys.VLAN)
		}
		if keys.AppProto != "http" {
			t.Fatalf("app_proto=%q", keys.AppProto)
		}
	})

	t.Run("scalar vlan and numeric flow_id as float", func(t *testing.T) {
		keys := suricataEVEJoinKeys(map[string]interface{}{
			"flow_id": float64(42), "vlan": float64(100), "app_proto": "TLS",
		})
		if keys.FlowID != 42 || keys.VLAN != 100 || keys.AppProto != "tls" {
			t.Fatalf("keys=%+v", keys)
		}
	})

	t.Run("missing values stay zero", func(t *testing.T) {
		keys := suricataEVEJoinKeys(map[string]interface{}{})
		if keys.CommunityID != "" || keys.FlowID != 0 || keys.VLAN != 0 || keys.AppProto != "" {
			t.Fatalf("absent members must not be invented: %+v", keys)
		}
	})

	t.Run("malformed flow_id is ignored, not fatal", func(t *testing.T) {
		keys := suricataEVEJoinKeys(map[string]interface{}{"flow_id": "not-a-number"})
		if keys.FlowID != 0 {
			t.Fatalf("flow_id=%d, want 0", keys.FlowID)
		}
	})
}

func TestSuricataEVEL7Values(t *testing.T) {
	t.Run("http", func(t *testing.T) {
		l7 := extractSuricataEVEL7(decodeEVE(t, eveAlertHTTP))
		if l7.HTTPHost != "jjc.sru.edu.cn" {
			t.Fatalf("http_host=%q", l7.HTTPHost)
		}
		if l7.HTTPMethod != "GET" {
			t.Fatalf("http_method=%q", l7.HTTPMethod)
		}
		if l7.Direction != "to_server" {
			t.Fatalf("direction=%q", l7.Direction)
		}
	})

	t.Run("tls sni and both ja hashes", func(t *testing.T) {
		l7 := extractSuricataEVEL7(decodeEVE(t, eveAlertTLS))
		if l7.TLSSNI != "portal.sru.edu.cn" {
			t.Fatalf("tls_sni=%q", l7.TLSSNI)
		}
		if l7.TLSJA3 != "a0e2f2759c0e0d0f8e6b4d3c2a1b0f9e" {
			t.Fatalf("tls_ja3=%q", l7.TLSJA3)
		}
		if l7.TLSJA4 != "t13d1516h2_8daaf6152771_02713d6af862" {
			t.Fatalf("tls_ja4=%q", l7.TLSJA4)
		}
	})

	t.Run("bare-string ja3 from older output", func(t *testing.T) {
		l7 := extractSuricataEVEL7(map[string]interface{}{
			"tls": map[string]interface{}{"ja3": "deadbeef"},
		})
		if l7.TLSJA3 != "deadbeef" {
			t.Fatalf("tls_ja3=%q, want the bare string form", l7.TLSJA3)
		}
	})

	t.Run("dns name from queries array", func(t *testing.T) {
		l7 := extractSuricataEVEL7(decodeEVE(t, eveAlertDNSMulti))
		if l7.DNSQuery != "upd2.sangfor.com.cn" {
			t.Fatalf("dns_query=%q, want the name from dns.queries[]", l7.DNSQuery)
		}
	})

	t.Run("dns rrname preferred when present", func(t *testing.T) {
		l7 := extractSuricataEVEL7(map[string]interface{}{
			"dns": map[string]interface{}{"rrname": "single.example"},
		})
		if l7.DNSQuery != "single.example" {
			t.Fatalf("dns_query=%q", l7.DNSQuery)
		}
	})
}

// The alert record must carry the join keys and L7 values next to the payload,
// because the correlation query reads them from the alert row.
func TestSanitizeSuricataAlertCarriesJoinKeysAndL7(t *testing.T) {
	event := decodeEVE(t, eveAlertTLS)
	out := sanitizeSuricataAlert(event, "ET MALWARE Suspicious TLS SNI", "medium")

	if out["community_id"] != "1:woTLgJZJZuGEl4+3DYwxkLR/i8I=" {
		t.Fatalf("community_id=%v", out["community_id"])
	}
	if out["sensor"] != "mirror0" {
		t.Fatalf("sensor=%v", out["sensor"])
	}
	if out["tls_sni"] != "portal.sru.edu.cn" {
		t.Fatalf("tls_sni=%v", out["tls_sni"])
	}
	if out["tls_ja3"] == "" || out["tls_ja4"] == "" {
		t.Fatalf("ja3/ja4 dropped: ja3=%v ja4=%v", out["tls_ja3"], out["tls_ja4"])
	}
	if out["vlan"] != uint16(39) {
		t.Fatalf("vlan=%v", out["vlan"])
	}
	// The raw TLS block must survive too: downstream evidence views read it.
	if _, ok := out["tls"].(map[string]interface{}); !ok {
		t.Fatal("tls block was dropped from the alert payload")
	}
}

// Sessions come from local-mirror, whose shape differs from EVE. Both the flat
// and the nested-content forms must resolve.
func TestTrafficSessionJoinAndL7BothShapes(t *testing.T) {
	t.Run("flat", func(t *testing.T) {
		join, l7 := trafficSessionJoinAndL7(map[string]interface{}{
			"sensor_id": "local",
			"app_protocol": "HTTP",
			"http_host": "www.example.test",
			"http_path": "/a",
			"tls_sni":   "sni.example.test",
			"dns_query": "q.example.test",
			"direction": "ingress",
			"vlan":      float64(39),
		})
		if join.Sensor != "local" || join.AppProto != "http" || join.VLAN != 39 {
			t.Fatalf("join=%+v", join)
		}
		if l7.HTTPHost != "www.example.test" || l7.HTTPURI != "/a" {
			t.Fatalf("l7=%+v", l7)
		}
		if l7.TLSSNI != "sni.example.test" || l7.DNSQuery != "q.example.test" {
			t.Fatalf("l7=%+v", l7)
		}
		if l7.Direction != "ingress" {
			t.Fatalf("direction=%q", l7.Direction)
		}
	})

	t.Run("nested content", func(t *testing.T) {
		join, l7 := trafficSessionJoinAndL7(map[string]interface{}{
			"content": map[string]interface{}{
				"app_protocol": "DNS",
				"dns_query":    "nested.example.test",
			},
		})
		if join.AppProto != "dns" {
			t.Fatalf("app_proto=%q", join.AppProto)
		}
		if l7.DNSQuery != "nested.example.test" {
			t.Fatalf("dns_query=%q", l7.DNSQuery)
		}
	})

	t.Run("absent stays empty", func(t *testing.T) {
		join, l7 := trafficSessionJoinAndL7(map[string]interface{}{})
		if join.CommunityID != "" || join.FlowID != 0 || join.VLAN != 0 {
			t.Fatalf("join=%+v", join)
		}
		if l7.HTTPHost != "" || l7.TLSSNI != "" || l7.DNSQuery != "" {
			t.Fatalf("l7=%+v", l7)
		}
	})
}
