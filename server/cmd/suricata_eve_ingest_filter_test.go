package main

import (
	"encoding/json"
	"testing"
)

// Realistic EVE records captured from a sensor running the standard Suricata
// profile. dns/flow/http/tls dominate the file (~99% of lines), which is
// exactly why ingestSuricataEVELine is fronted by a byte-level prefilter.
const (
	eveFilterDNSLine = `{"timestamp":"2026-11-09T16:01:20.113402+0000","flow_id":2130713661621199,"in_iface":"mirror0","event_type":"dns","vlan":[39],"src_ip":"10.1.1.181","src_port":52449,"dest_ip":"10.1.18.253","dest_port":53,"proto":"UDP","dns":{"type":"query","id":40123,"rrname":"update.microsoft.com","rrtype":"A","tx_id":0}}`

	eveFilterFlowLine = `{"timestamp":"2026-11-09T16:01:20.228911+0000","flow_id":2130713661621201,"in_iface":"mirror0","event_type":"flow","vlan":[39],"src_ip":"10.1.1.181","src_port":52451,"dest_ip":"10.1.18.253","dest_port":161,"proto":"UDP","app_proto":"failed","flow":{"pkts_toserver":2,"pkts_toclient":0,"bytes_toserver":140,"bytes_toclient":0,"start":"2026-11-09T16:01:20.228911+0000","end":"2026-11-09T16:01:22.229110+0000","age":2,"state":"new","reason":"timeout"}}`

	eveFilterHTTPLine = `{"timestamp":"2026-11-09T16:01:21.502337+0000","flow_id":2130713661621233,"in_iface":"mirror0","event_type":"http","vlan":[39],"src_ip":"10.1.1.181","src_port":52460,"dest_ip":"10.1.18.253","dest_port":80,"proto":"TCP","app_proto":"http","http":{"hostname":"update.microsoft.com","url":"/v6/ClientWebService/client.asmx","http_user_agent":"Microsoft-CryptoAPI/10.0","http_method":"POST","protocol":"HTTP/1.1","status":200,"length":0}}`

	eveFilterTLSLine = `{"timestamp":"2026-11-09T16:01:22.771045+0000","flow_id":2130713661621288,"in_iface":"mirror0","event_type":"tls","vlan":[39],"src_ip":"10.1.1.181","src_port":52471,"dest_ip":"10.1.18.253","dest_port":443,"proto":"TCP","app_proto":"tls","tls":{"subject":"CN=update.microsoft.com","issuerdn":"CN=Microsoft RSA TLS CA 01","serial":"00A1B2C3","fingerprint":"aa:bb:cc:dd","sni":"update.microsoft.com","version":"TLS 1.2","notbefore":"2026-01-01T00:00:00","notafter":"2027-01-01T00:00:00"}}`

	// Real production alert line: event_type sits in the middle of the object,
	// exactly the shape that a fixed-offset prefilter would miss.
	eveFilterMetalertLine = `{"timestamp":"2026-11-09T16:01:27.692703+0000","flow_id":2130713661621830,"in_iface":"mirror0","event_type":"alert","vlan":[39],"src_ip":"10.1.1.181","src_port":52449,"dest_ip":"10.1.18.253","dest_port":161,"proto":"UDP","alert":{"severity":2,"signature":"GPL SNMP public access udp","signature_id":2101411}}`
)

func TestSuricataEVELineIsAlert(t *testing.T) {
	cases := []struct {
		name string
		line string
		want bool
	}{
		{"real_dns_line", eveFilterDNSLine, false},
		{"real_flow_line", eveFilterFlowLine, false},
		{"real_http_line", eveFilterHTTPLine, false},
		{"real_tls_line", eveFilterTLSLine, false},
		{"real_alert_line_event_type_first", `{"event_type":"alert","timestamp":"2026-11-09T16:01:27.692703+0000","src_ip":"10.1.1.181","dest_ip":"10.1.18.253","alert":{"signature_id":2101411,"signature":"GPL SNMP public access udp","severity":2}}`, true},
		{"real_alert_line_event_type_mid", eveFilterMetalertLine, true},
		{"alert_line_with_spaces", `{"event_type": "alert", "timestamp": "2026-11-09T16:01:27.692703+0000"}`, true},
		{"alert_line_with_space_before_colon", `{"event_type" : "alert"}`, true},
		{"alert_line_case_insensitive", `{"event_type":"ALERT"}`, true},
		{"empty_line", ``, false},
		{"whitespace_only", "   \t ", false},
		// A truncated tail is not a complete member: the value never closes.
		// This is safe because the reader loop stores the fragment in `pending`
		// and concatenates it with the next chunk, so the completed alert line
		// is re-evaluated (and then accepted) on the following tick.
		{"truncated_half_line", `{"timestamp":"2026-11-09T16:01:27.692703+0000","event_type":"ale`, false},
		// The literal "alert" appears only as a nested object name, not as the
		// event_type value; a naive strings.Contains would wrongly accept it.
		{"alert_key_but_dns_event_type", `{"event_type":"dns","alert":{}}`, false},
		{"alert_key_before_event_type", `{"alert":{"signature":"x"},"event_type":"flow"}`, false},
		{"alert_substring_in_signature", `{"event_type":"http","http":{"url":"/alert/status"}}`, false},
		{"non_alert_similar_event_type", `{"event_type":"alertx"}`, false},
		{"missing_event_type", `{"timestamp":"2026-11-09T16:01:20.113402+0000","src_ip":"10.1.1.181"}`, false},
		// An escaped spelling of the same value must not be rejected: the
		// prefilter fails open so the real decoder can decide.
		{"escaped_alert_event_type", `{"event_type":"ale\u0072t"}`, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := suricataEVELineIsAlert(tc.line); got != tc.want {
				t.Fatalf("suricataEVELineIsAlert(%q) = %v, want %v", tc.line, got, tc.want)
			}
		})
	}
}

// The prefilter must never reject a line that the full decoder would treat as
// an alert. This guards the fail-open contract on the shapes the reader loop
// actually feeds in.
func TestSuricataEVELineIsAlertNeverDropsRealAlerts(t *testing.T) {
	for _, line := range []string{eveFilterMetalertLine, testSuricataAlertLine} {
		if !suricataEVELineIsAlert(line) {
			t.Fatalf("prefilter dropped a real alert line: %q", line)
		}
	}
}

// eveFilterSampleMix mimics the observed sensor make-up: ~99% non-alert
// records with a single alert. It lets the benchmarks below compare the
// prefilter against decoding every line.
func eveFilterSampleMix() []string {
	mix := make([]string, 0, 100)
	for i := 0; i < 24; i++ {
		mix = append(mix, eveFilterDNSLine, eveFilterFlowLine)
	}
	for i := 0; i < 24; i++ {
		mix = append(mix, eveFilterHTTPLine, eveFilterTLSLine)
	}
	mix = append(mix, eveFilterDNSLine, eveFilterDNSLine, eveFilterDNSLine, eveFilterMetalertLine)
	return mix
}

func BenchmarkSuricataEVEPrefilter(b *testing.B) {
	lines := eveFilterSampleMix()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		for _, line := range lines {
			suricataEVELineIsAlert(line)
		}
	}
}

func BenchmarkSuricataEVEUnmarshalAll(b *testing.B) {
	lines := eveFilterSampleMix()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		for _, line := range lines {
			var event map[string]interface{}
			_ = json.Unmarshal([]byte(line), &event)
		}
	}
}
