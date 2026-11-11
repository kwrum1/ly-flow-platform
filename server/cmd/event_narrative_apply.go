package main

// applyEventNarrative attaches the human-readable explanation and the display
// identity to an outgoing threat row.
//
// The list row keeps `summary` short (one sentence) because it is rendered in a
// table; `detail` goes with the event so the drawer can show the longer
// explanation without a second request.
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
	// Display identity, so the console can render "来源 → 受害服务器" from
	// labels instead of picking an arbitrary IP.
	if client := xdrPickString(source, "client_forwarded_for"); client != "" {
		threat["client_forwarded_for"] = client
	}
	if display := xdrPickString(source, "source_display"); display != "" {
		threat["source_display"] = display
	}
	if display := xdrPickString(source, "victim_display"); display != "" {
		threat["victim_display"] = display
	}
	if ip := xdrPickString(source, "victim_ip"); ip != "" {
		threat["victim_ip"] = ip
	}
}