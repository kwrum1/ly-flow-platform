map(
  select(.event_type == "flow" or .event_type == "alert" or .event_type == "dns" or .event_type == "http" or .event_type == "tls")
  | .suricata_version = "7.0.11"
  | .flow_id = (((.src_port - 53000) * 100000000) + 23456789)
)
| sort_by(({"alert": 0, "dns": 1, "http": 2, "tls": 3, "flow": 4}[.event_type]), .src_port, .pcap_cnt, .timestamp)
| .[]
