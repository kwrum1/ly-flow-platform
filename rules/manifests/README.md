# Rule Source Manifests

The source of truth for each rule corpus is stored next to the corpus directory:

- `rules/internal/hids/lyflow/manifest.json`
- `rules/internal/hids/elkeid-rebuilt/manifest.json`
- `rules/internal/dpi/lyflow/manifest.json`
- `rules/subscriptions/wazuh-auditd/manifest.json`
- `rules/subscriptions/elastic-linux/manifest.json`
- `rules/subscriptions/falco/manifest.json`
- `rules/subscriptions/suricata/manifest.json`

Manifests define source ownership, license, local raw path, converted output path, default activation state, and conversion target IR.

External sources are not auto-fetched or auto-activated by these manifests. They require a later explicit fetch/convert/validate step.
