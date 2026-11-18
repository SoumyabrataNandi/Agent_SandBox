# U6 Escape Suite + Release — Design Questions

Answer after each `[Answer]:` tag, or reply **"accept recommended defaults"**.

### Question 1 — Where the escape suite lives
A) A dedicated workspace crate `tests/escape-suite` (black-box via `RunService` and the binary), so it can't depend on internals **(Recommended)**
B) Spread across the existing crates' test folders
C) Other (please describe after [Answer]: tag below)

[Answer]: 

### Question 2 — Release targets
A) Linux x86_64 + aarch64 (glibc), macOS arm64 + x86_64, Windows x86_64 (MSVC) **(Recommended; matches NFR-1)**
B) A plus fully static Linux (musl) builds
C) Other (please describe after [Answer]: tag below)

[Answer]: 

### Question 3 — How releases are published
A) Push a `v*` tag → CI builds, runs the escape suite per target, and creates a **draft** GitHub Release with archives + `SHA256SUMS`. You review and publish **(Recommended)**
B) Fully automatic public release on tag
C) Build artifacts only (no GitHub Release)
D) Other (please describe after [Answer]: tag below)

[Answer]: 

### Question 4 — Performance check in CI
A) Release-mode smoke check with generous bounds (2× the NFR-3 targets), printing the calibration table. Catches big regressions without flaky failures **(Recommended)**
B) Strict NFR-3 bounds (may be flaky on shared CI runners)
C) No performance check in CI
D) Other (please describe after [Answer]: tag below)

[Answer]: 

### Question 5 — OTLP exporter (deferred from U5)
A) Defer to the next cycle; documented as a known gap in the threat model / README **(Recommended; keeps the release focused on isolation)**
B) Implement it in U6 behind the `otel` feature
C) Other (please describe after [Answer]: tag below)

[Answer]: 

### Question 6 — Supply-chain provenance for release binaries
A) `SHA256SUMS` + GitHub build-provenance attestation (`actions/attest-build-provenance`), verifiable with `gh attestation verify` **(Recommended)**
B) `SHA256SUMS` only
C) Also sign with cosign (keyless)
D) Other (please describe after [Answer]: tag below)

[Answer]: 
