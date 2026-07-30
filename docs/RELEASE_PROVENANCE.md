# Release provenance

Offline releases are fail-closed. The builder does not pull images, update scanner databases, resolve modules, or fetch package metadata. Every required base image must already exist locally and be supplied as a `repository@sha256:digest` reference.

## Required inputs

- `RELEASE_SIGNING_KEY`: external Ed25519 private key. The corresponding public `release-root.pem` is distributed out of band and must not be placed in the package.
- `RELEASE_ID` and `SOURCE_DATE_EPOCH`: stable release identity and archive timestamp. They default to the current Git commit only for local verification.
- `NGINX_IMAGE` and `SURICATA_PROFILE_IMAGE`: locally present digest references.
- `RASP_PYTHON_310_IMAGE`, `RASP_PYTHON_311_IMAGE`, and `RASP_PYTHON_312_IMAGE`: locally inspectable immutable references for the three required RASP conformance runtimes. The release builder rejects missing, mutable, or malformed values before compilation.
- For non-amd64 releases, architecture-specific digest references in `DB_POSTGRES_IMAGE`, `DB_REDIS_IMAGE`, and `DB_CLICKHOUSE_IMAGE`.
- Local, versioned advisory databases for npm, Python, Go, and image scanners. Missing database identity blocks release.

Gitea CI runs `scripts/qa/prepare-rasp-conformance-images.sh` before package construction. The helper reuses an existing local conformance tag or builds a missing tag from the checked-in Dockerfile for `linux/amd64` with pulls disabled, no cache, and provenance disabled. It emits the three ordered content-addressed references, preferring a repository digest and falling back to the local image ID, and the workflow maps them directly to the required release inputs.

RASP conformance images are release-verification inputs only. They are not members of the packaged `IMAGES` array, are not written to `image-pins.tsv`, and are not included in `images/lyflow-images.tar.gz`.

The builder runs `scripts/qa/generate-release-evidence.sh` before compilation. Any `BLOCKED` or `FAIL` scanner row stops the build. An empty scanner response without a locally provable database version is `BLOCKED`, not clean.

## Produced evidence

The package contains deterministic CycloneDX 1.5 SBOMs for npm, Go, Python, Java, and container inputs. Raw scanner output and `scanner-summary.json` record tool and database versions. Reachable high or critical findings block release unless listed in the validated exception document.

Each exception requires an ID, component, high/critical severity, owner, reachability evidence, compensating control, expiry after evidence generation but no more than 30 days later, and scanner name/version/database version. `scripts/release-provenance.sh validate-exceptions` enforces the schema.

## Signature chain

1. `rules/rules-manifest.sha256` covers every packaged rule file and is signed as `rules-manifest.sha256.sig`.
2. `release-manifest.sha256` covers the rule manifest/signature and every other package payload file, excluding only itself and its signature.
3. `release-manifest.sha256.sig` is a raw Ed25519 signature over the exact manifest bytes.
4. The outer normalized archive has a `.sha256` sidecar and raw Ed25519 `.sha256.sig` sidecar.
5. `install-offline.sh --trust-root /external/release-root.pem` installs the external public root, verifies the release and rule manifests, and only then checks Docker, copies files, loads images, or starts services.

Candidate traffic provenance is recorded in `candidate-traffic-ledger.json`. Its five-source catalog binds vendor identity, license, raw-payload SHA-256 before decompression, parser, converter, and deduplication policy. Every retained candidate signature records its source IDs and converted-content SHA-256. The Ed25519 ledger signature and external public root allow the complete lineage to be verified without network access; missing source pins, altered converted bytes, unknown source IDs, or an unsigned ledger fail closed. Candidate counts are not reported as runtime-loaded counts. After lifecycle activation, the signed active manifest and its verified bundle are authoritative for active and runtime health counts.

## Reproducibility limits

Normalized tar ordering, numeric ownership, timestamps, POSIX metadata, and gzip headers make the same staged package byte-identical. This does not establish that two clean application builds are identical.

The remaining non-reproducible layers are Docker save metadata/order below the normalized outer gzip, certificate generation in the frontend Dockerfile, APK repository state when a base is not digest-pinned, the externally supplied CGO ARM agent, and any locally cached application image accepted by the CI cache path. Two clean builds with identical digest inputs must compare all image and archive digests before a full reproducibility claim is allowed.
