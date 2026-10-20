# Development scripts

All scripts are intended to run from the repository root or via their path.

## `test-all.sh`

```bash
scripts/dev/test-all.sh fast   # unit tests + frontend + policy checks (CI default)
scripts/dev/test-all.sh full   # every Go module + frontend (integration tests may need services)
```

Requirements:

- Go 1.26.5 (the script sets `GOTOOLCHAIN=auto` and `GOSUMDB=sum.golang.org`)
- Node.js 22+ and npm
- Docker Compose for optional compose validation

## Policy checks

```bash
scripts/dev/check-secrets.sh
scripts/dev/check-private.sh
scripts/dev/check-licenses.sh
```

- `check-secrets.sh`: blocks known credentials, private keys and tracked `.env` files.
- `check-private.sh`: keeps `private/` and Elkeid HUB/Console out of public builds.
- `check-licenses.sh`: blocks known AGPL/SSPL dependencies; runs `go-licenses` /
  `license-checker` when available.

## Environment

- Build host and test host addresses/credentials live in
  `/opt/lyflow/ENVIRONMENT.local.md` on the build machine (not in git).
- Never commit passwords, keys or real customer data.
