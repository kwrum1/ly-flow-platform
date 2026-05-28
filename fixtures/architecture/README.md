# LyFlow Architecture Scenario Fixtures

Deterministic fixture pack for the five-layer architecture QA path.

## Scenarios

- `benign-flow`: normal health/API traffic.
- `suspicious-domain`: semantic flow to a suspicious external domain.
- `login-anomaly`: repeated authentication failure behavior.
- `upload-admin-access`: upload plus sensitive admin access.
- `runtime-suspicious-process`: suspicious shell/network process execution.
- `rasp-sqli`: Python/Java RASP SQL injection signal.
- `multi-stage-attack-chain`: correlated DPI + Runtime + RASP + XDR chain with `chain_id=lyfixture-chain-001`.

## Usage

```bash
python3 fixtures/architecture/load_fixtures.py --out /tmp/lyflow-fixtures
python3 fixtures/architecture/load_fixtures.py --cleanup --out /tmp/lyflow-fixtures
```

The loader writes JSONL files by stream/API surface. It does not require internet access and does not delete unrelated records.
