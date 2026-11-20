# C3-U4 Sessions — Design Questions

Answer each by putting a letter after `[Answer]:`. Option **A** is the recommendation in every case. "accept recommended defaults" = all A.

## Q1 Which interpreter a session starts from
A) **The snapshot**, via a new `sandboxd-session` export in the custom interpreters (one more interpreter release). The upstream interpreter is the fallback (`snapshots = off`, or below the memory floor). **(Recommended: fast creation; the preloaded modules are available in sessions too)**
B) Upstream interpreter only (no new release; session creation ≈ a cold start, 30–150 ms)

[Answer]: A

## Q2 A second call arrives while a call in the same session is still running
A) **Refused with `409 SESSION_BUSY`**: deterministic, and the agent decides whether to retry. **(Recommended)**
B) Queued until the running call finishes (up to the queue timeout)

[Answer]: A

## Q3 Server-wide session cap (each session holds an interpreter and its memory)
A) **`[runtime] max_sessions`, default 16**, in addition to each policy's `session.max_sessions`. The pool is sized for it. **(Recommended: bounded memory even if every policy allows 100)**
B) Only the per-policy limit

[Answer]: A

## Q4 Input files in sessions
A) **Files may be sent at creation and with each call.** They are added under `/in` (read-only to the guest). Re-using a name already present → `400`. **(Recommended)**
B) Only at creation

[Answer]: A

## Q5 What a CPU or wall-clock limit inside a call does
A) **Ends the session** (state may be half-updated): the result has `limits_hit` and `session_ended: "limit"`; later calls get `404`. **(Recommended; as in requirement SE1.4)**
B) Keep the session alive and only fail the call

[Answer]: A
