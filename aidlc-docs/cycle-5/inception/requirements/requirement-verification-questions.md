# Cycle 5 — Requirements Verification Questions (usability: first start, packages, container)

## Starting point
v0.1.0 is tagged and drafted (cycle 4). The cycle 4 pilot and release work left three gaps:
- **F1, first start:** `sandboxd mcp` builds its cache and snapshots *before* answering `initialize` (about 20 s for a release build, 65 s for debug). MCP clients with a 30 s connect timeout can give up. Today the only mitigation is documentation (`sandboxd cache warm`).
- **No third-party Python packages.** Only the stdlib is available. Many agent tasks want small pure-Python libraries (`attrs`, `tabulate`, `python-dateutil`, `pyyaml` in pure mode, `jinja2`, …). `pip install` inside a sandbox is out (network, supply chain).
- **No container image.** Teams running services want `docker run` / Kubernetes, not a tarball.

User instruction (2026-11-24): *"continue with cycle 5"*. The user's standing instruction from cycle 4 ("all are approved from my end and select all default values") is applied: every answer below is the recommended option.

---

### Question 1 — Scope
A) **All three:** non-blocking MCP start-up, operator-curated pure-Python packages, a container image; then release v0.2.0. **(Recommended)**
B) Start-up fix + packages only
C) Other

[Answer]: A

### Question 2 — Start-up behaviour (stdio MCP)
A) **Answer `initialize` and `tools/list` immediately**, build the sandbox in the background, and make tool calls **wait** for it. When the client asked for progress, a waiting call reports "sandboxd is starting". If the build fails, every tool call returns that error (the server stays up so the client can show it). The HTTP server is unchanged: it still listens only when ready, so `/healthz` stays an honest readiness probe. **(Recommended)**
B) Same for HTTP too (listen first, `/healthz` reports starting)
C) Keep docs only

[Answer]: A

### Question 3 — Where packages come from
A) **An operator wheelhouse:** `[packages] dir = "<path>"` holding `.whl` files. sandboxd accepts **pure-Python wheels only** (tag `py3-none-any` or `py2.py3-none-any`, and no `.so`/`.pyd`/`.dll`/`.dylib` inside), verifies each file's SHA-256 against an optional `[packages] sha256` lock, extracts them once into the cache (content-addressed), and mounts the result read-only in every Python run. Agents can't install anything. **(Recommended: deny-by-default stays intact; the operator controls the supply chain)**
B) Agents may `pip install` from an allowlisted index through the network broker
C) Other

[Answer]: A

### Question 4 — Which runs see packages
A) **Every Python run, unless the policy opts out** with `[python] packages = false`. Packages are appended to the end of `sys.path`, so they can never shadow the stdlib. **(Recommended: simple; the operator already chose the wheelhouse)**
B) Opt-in per policy
C) Per-policy package lists

[Answer]: A

### Question 5 — Container image
A) **`ghcr.io/<owner>/sandboxd`**, built by `release.yml` from the release's Linux binaries (amd64 + arm64) on `debian:trixie-slim`, running as a non-root user, `sandboxd serve` on `0.0.0.0:8080` with a default config, cache in a volume (`/var/cache/sandboxd`). It is smoke-tested (`version`, `/healthz`, one run) before the push, and tagged with the version and `latest`. **(Recommended)**
B) Distroless base (smaller, no shell for debugging)
C) Not this cycle

[Answer]: A

### Question 6 — Release
A) **v0.2.0** after CI is green: the same draft-release flow, plus the image. The image is pushed when the release workflow runs (it can't stay a draft); you publish the GitHub release. **(Recommended)**
B) No release this cycle

[Answer]: A
