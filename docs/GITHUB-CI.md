# GitHub cloud build

LyFlow keeps two Git remotes:

- `gitea`: internal source hosting and local recovery.
- `github`: public collaboration, cloud CI, and firmware releases.

The GitHub workflow runs on fresh hosted virtual machines. It does not use
`actions/cache`, Go build caches, npm caches, or Docker layer caches. Vendor
images are pulled for every run and product images use `--pull --no-cache`.

Before architecture builds start, the rules job downloads the current public
payloads for ET Open, OISF Traffic ID, Snort Community, Stamus Lateral, and
Positive Technologies AttackDetection. It records upstream SHA256 values,
converts supported signatures into LyFlow rule IR, deduplicates them, and passes
that immutable current-run snapshot to both architecture jobs.

The release contains separate `amd64` and `arm64` offline installation bundles.
Each installer rejects a package whose architecture does not match the host.

## Push to both hosts

```bash
git push gitea main
git push github main
git push gitea --tags
git push github --tags
```

Gitea workflow files remain under `.gitea/workflows/`. GitHub workflow files
live under `.github/workflows/`; neither CI system depends on the other.
