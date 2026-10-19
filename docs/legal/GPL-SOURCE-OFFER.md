# GPL source offer

`ly_probe` is distributed as a separate executable/container under GPL-3.0.
LyFlow does not link `ly_probe` into its proprietary binaries.

For every binary distribution of `ly_probe`, the corresponding source is:

- Upstream: https://github.com/Abyssal-Fish-Technology/ly_probe
- Pinned revision: `06c097dd5c69e391efd3c8b3776d672e03386e49`
- LyFlow patch: `patches/lyprobe/0001-hot-reload.patch`
- Build recipe: `scripts/dev/lyprobe-build.sh`
- Runtime package: `lyprobe` + `liblyprobe-1.0.0.so` + `plugins/servicePlugin.so`

The build recipe is deterministic, uses the upstream source tree unchanged
except for the published patch, and records `BUILD-INFO`/`SHA256SUMS` next to
the artifacts.

## Written offer

For a period of three years after distribution, the distributor will provide
the complete corresponding source code for the GPL-covered components on a
durable medium for no more than the cost of physically performing the source
distribution. Requests must include the product version and the `BUILD-INFO`
revision.

The public source repository and the pinned upstream URL above are the primary
source locations. Release engineers must include the source bundle or a valid
written offer with every public binary/image release of `ly_probe`.

Suricata is also GPL-2.0 and is distributed as a separate container; the same
source-distribution obligation applies using the pinned Suricata release from
its upstream repository.
