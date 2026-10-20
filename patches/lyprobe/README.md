# ly_probe patches

Upstream: `https://github.com/Abyssal-Fish-Technology/ly_probe.git`
Pinned revision: `06c097dd5c69e391efd3c8b3776d672e03386e49`

## 0001-hot-reload.patch

Adds zero-downtime fingerprint reload to `plugins/servicePlugin.c`:

- Reads all five `fp-patterns/*.json` files into a new in-memory rule set.
- Swaps the rule set under a `pthread_rwlock` only after every file parses.
- A detached watcher thread polls inode/size/mtime every 2 seconds and
  hot-reloads after an atomic rename.
- Packet matching takes the read lock; a failed parse keeps the old rules.

Apply order is lexical. The build script copies `*.patch` from this directory
into the temporary source tree and runs `git apply` before `autogen.sh`.

The patch is a thin integration change only; upstream capture/flow algorithms
are untouched. Keep the patch rebased when the pinned revision changes.
