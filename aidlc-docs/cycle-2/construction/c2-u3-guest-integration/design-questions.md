# C2-U3 Guest Integration — Design Questions

Answer each by putting a letter after `[Answer]:`. Option **A** is the recommendation in every case. "accept recommended defaults" = all A.

## Q1 JavaScript bootstrap mechanism
A) `qjs -m -I boot.mjs /code/main.mjs`: QuickJS's include flag runs the bootstrap first, with no wrapper frames and `scriptArgs` unchanged (amends ADR-C2-3)
B) As in ADR-C2-3: `qjs -m boot.mjs /code/main.mjs`, where boot does `await import('/code/main.mjs')` and fixes `scriptArgs` (one extra frame in errors from top-level code)

[Answer]: A

## Q2 How Python HTTP reaches the broker
A) Patch `http.client` (`HTTPConnection.connect` → device socket; provide `HTTPSConnection`). urllib, http.client and HTTPS all go through `/dev/sandbox/http` and HTTP rules, with stdlib response parsing.
B) Custom urllib handlers only. `http.client` would then use raw TCP (`socket.create_connection`) and need TCP rules, and HTTPS through `http.client` would not work (no `ssl` in WASI).

[Answer]: A

## Q3 Exceptions from `urllib.request.urlopen`
A) Same shape as the stdlib: `URLError` whose `.reason` is the built-in exception (`PermissionError`, `TimeoutError`, …); HTTP 4xx/5xx → `HTTPError`
B) Raise the built-in exception directly (not catchable by `except URLError`)

[Answer]: A

## Q4 Exception types in `sandbox_net`, `http.client` and `socket`
A) Built-in exceptions (`PermissionError`, `TimeoutError`, `ConnectionError`, `socket.gaierror`, `OSError`) with a `.code` attribute holding the broker code
B) A `sandbox_net.NetworkError` hierarchy that also inherits the built-ins (tracebacks show `sandbox_net.…Error`)

[Answer]: A

## Q5 How the guest learns "no grant" and the policy name (for N2.3 messages)
A) A tiny read-only `/dev/sandbox/info` device (`{"policy", "http", "tcp"}`), opened only on failure paths
B) No device: a generic message without the policy name ("network access is not allowed by the sandbox policy")
C) Pass it on the command line to the bootstrap (needs `scriptArgs` surgery in JS)

[Answer]: A

## Q6 Where the helper sources live
A) `crates/sandboxd-runtime/guest/`, embedded with `include_str!` (the crate is self-contained)
B) Top-level `guest/`, as sketched in the application design

[Answer]: A

## Q7 A policy grants network, but the runtime has no broker (library use, or a misconfiguration)
A) Refuse the run: `POLICY_VIOLATION` "this policy grants network access, but network access is not configured on this runtime" (the guest never starts)
B) Run anyway with the network unavailable (the guest gets "not allowed")

[Answer]: A

## Q8 The unused cycle-1 `NetworkBroker` seam trait in `sandboxd-runtime`
A) Remove it; the runtime uses the concrete `sandboxd_net::Broker` (it was a placeholder, not part of the HTTP/CLI/MCP APIs)
B) Keep it and implement it for `Broker`

[Answer]: A
