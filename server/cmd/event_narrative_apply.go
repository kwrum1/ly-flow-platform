package main

// applyEventNarrative attaches the human-readable explanation and the endpoint
// identity to an outgoing threat row.
//
// The list row keeps `narrative` short (one sentence) because it is rendered in
// a table; `narrative_detail` goes with the event so the drawer can show the
// longer explanation without a second request.
//
// Endpoint identity is derived from the event itself rather than only from the
// promoted columns, because the columns were added recently and every event
// stored before that has them empty. Falling back to the nested payload is what
// makes existing rows explain correctly without rewriting the database.
func applyEventNarrative(threat map[string]interface{}, source map[string]interface{}) {
	if threat == nil || source == nil {
		return
	}
	summary, detail := eventNarrativeFromEvent(source)
	if summary != "" {
		threat["narrative"] = summary
	}
	if detail != "" {
		threat["narrative_detail"] = detail
	}

	httpBlock := asMap(source["http"])
	if len(httpBlock) == 0 {
		httpBlock = asMap(asMap(source["eve"])["http"])
	}
	tlsBlock := asMap(source["tls"])
	if len(tlsBlock) == 0 {
		tlsBlock = asMap(asMap(source["eve"])["tls"])
	}
	dnsBlock := asMap(source["dns"])
	if len(dnsBlock) == 0 {
		dnsBlock = asMap(asMap(source["eve"])["dns"])
	}

	// The victim is the wire destination: that is the host the packet was sent
	// to, and the only endpoint the evidence actually attests to.
	victimIP := firstNonEmpty(
		xdrPickString(source, "victim_ip"),
		xdrPickString(source, "dst_ip"),
		xdrPickString(source, "dest_ip"),
		xdrPickString(source, "destination_ip"),
		xdrPickString(source, "entities.target_ip"),
		xdrPickString(asMap(source["eve"]), "dest_ip"),
	)
	if victimIP != "" {
		threat["victim_ip"] = victimIP
	}

	// The victim display is the address plus, when known, the requested domain
	// as context. The domain never replaces the address.
	requestedDomain := firstNonEmpty(
		xdrPickString(source, "requested_domain"),
		xdrPickString(source, "http_host"),
		xdrPickString(httpBlock, "hostname"),
		xdrPickString(source, "tls_sni"),
		xdrPickString(tlsBlock, "sni"),
		xdrPickString(source, "dns_query"),
		xdrPickString(dnsBlock, "rrname"),
	)
	if requestedDomain != "" {
		threat["requested_domain"] = requestedDomain
	}
	switch {
	case victimIP != "" && requestedDomain != "" && requestedDomain != victimIP:
		threat["victim_display"] = victimIP + "（请求域名 " + requestedDomain + "）"
	case victimIP != "":
		threat["victim_display"] = victimIP
	case requestedDomain != "":
		threat["victim_display"] = "未知目标（请求域名 " + requestedDomain + "）"
	default:
		threat["victim_display"] = "未知目标"
	}

	// Source display: the observed packet source, with the X-Forwarded-For claim
	// shown as a reference beside it rather than substituted for it.
	sourceIP := firstNonEmpty(
		xdrPickString(source, "src_ip"),
		xdrPickString(source, "source_ip"),
		xdrPickString(asMap(source["eve"]), "src_ip"),
	)
	if sourceIP != "" {
		threat["source_ip"] = sourceIP
	}
	threat["source_display"] = firstNonEmpty(sourceIP, "未知来源")

	// X-Forwarded-For is self-reported. Keep it available for recognition but
	// label it in the field name so no consumer mistakes it for the origin.
	if forwarded := firstNonEmpty(
		xdrPickString(source, "client_forwarded_for_observed"),
		xdrPickString(httpBlock, "xff"),
		xdrPickString(source, "client_forwarded_for"),
	); forwarded != "" && forwarded != sourceIP {
		threat["client_forwarded_for"] = forwarded
		threat["client_forwarded_for_note"] = "X-Forwarded-For，客户端自述，仅供参考"
	}
}
