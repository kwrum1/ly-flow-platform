# HIDS + DPI Rule Rollout and Rollback

This procedure activates compiled HIDS + DPI rule artifacts safely. It does not deploy RASP rules and does not execute response actions.

## Dry-run compile

```bash
python3 scripts/rule-rollout.py --dry-run --source rules/compiled/scored-preview --live rules/compiled/live --backup rules/compiled/backups
```

Dry-run validates that the source exists and reports the number of candidate JSON rule files. It must not modify live rules.

## Activate

```bash
python3 scripts/rule-rollout.py --activate --source rules/compiled/scored-preview --live rules/compiled/live --backup rules/compiled/backups
```

Activation creates a timestamped backup of the previous live directory, then copies the new compiled preview into `rules/compiled/live`.

## Rollback

```bash
python3 scripts/rule-rollout.py --rollback --live rules/compiled/live --backup rules/compiled/backups
```

Rollback restores the newest backup. If no backup exists, rollback fails safely without changing live rules.

## Operator notes

- HIDS and DPI only; RASP is deferred.
- Unsupported/quarantine rules must not be activated.
- Response candidates remain recommendations only.
- Hot update should restart or reload the components that read compiled rule files after activation.
