# C5-U3 Container image — Summary

**Requirements:** FR-CI1 · **AC:** 4

- **`packaging/container/Dockerfile`:**
  - `debian:trixie-slim` with `ca-certificates`; user `sandboxd` (uid 10001);
  - `/usr/local/bin/sandboxd` taken from `bin/${TARGETARCH}/`;
  - default config at `/etc/sandboxd/sandboxd.toml`: listen `0.0.0.0:8080`, cache `/var/cache/sandboxd` (a `VOLUME`), work `/var/lib/sandboxd/work`, policies `/etc/sandboxd/policies`, audit to stdout;
  - notices in `/usr/share/doc/sandboxd`; `EXPOSE 8080`; `CMD ["serve"]`.
- **`packaging/container/entrypoint.sh`:** `SANDBOXD_TOKENS="name=<sha256>,…"` adds bearer-token hashes to a copy of the default config in `/tmp`. Names and 64-hex hashes are validated, and the variable is refused with a custom config. The server already refuses to bind a non-loopback address without tokens.
- **`.dockerignore`:** the build context is only `bin/`, `packaging/container/` and the notices.
- **`release.yml` job `image`** (after `build`; `packages: write`, `id-token: write`, `attestations: write`):
  1. unpacks the two Linux release archives (the same binaries that passed the escape suite);
  2. builds an amd64 image with buildx (QEMU for arm64);
  3. smoke test: `version`, a container started with a fresh token that answers `/healthz`, an authenticated `print(6*7)` returning `42`, an unauthenticated request getting `401`, uid 10001 inside;
  4. pushes `ghcr.io/<owner>/sandboxd:<version>` and `:latest` for amd64 + arm64, with a build-provenance attestation pushed to the registry.
- **Docs:** GETTING_STARTED §9 covers the token, the cache volume, a custom config, `--read-only` with tmpfs, and TLS in front.

Verification happens in the v0.2.0 release run (Docker isn't available on the development laptop).
