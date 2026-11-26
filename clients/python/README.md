# sandboxd-client (Python)

Python client for [sandboxd](https://github.com/SoumyabrataNandi/Agent_SandBox), the WebAssembly
sandbox for code written by AI agents. Standard library only, Python ≥ 3.10.

## Install

The wheel is attached to each GitHub release:

```bash
pip install https://github.com/SoumyabrataNandi/Agent_SandBox/releases/download/v0.3.0/sandboxd_client-0.3.0-py3-none-any.whl
```

## Use

```python
from sandboxd_client import Sandboxd, SandboxdError

sbx = Sandboxd("http://127.0.0.1:8080", token="sbx_...")  # or SANDBOXD_URL / SANDBOXD_TOKEN

r = sbx.run("print(6*7)")
print(r.ok, r.stdout)                      # True 42

# Files are read-only under /in (text or bytes); files written to /out come back as artifacts.
r = sbx.run(
    "import csv\nrows = list(csv.reader(open('/in/data.csv')))\n"
    "open('/out/count.txt', 'w').write(str(len(rows)))",
    files={"data.csv": "a,b\n1,2\n"},
    limits={"wall_clock": "5s", "memory": "128MiB"},
)
print(r.artifact("count.txt").text())      # 2

# JavaScript
print(sbx.run("console.log([1, 2, 3].map(x => x * 2))", "javascript").stdout)

# Streaming: stdout/stderr/limit events as they happen, then the result.
for ev in sbx.stream("import time\nfor i in range(3):\n    print(i, flush=True)\n    time.sleep(0.2)"):
    if ev.type == "stdout":
        print("got", ev.text, end="")
    elif ev.type == "result":
        print("done:", ev.result.outcome)

# Sessions keep variables, imports and /work between runs (the policy must enable sessions).
with sbx.create_session(policy="notebook") as s:
    s.run("import json\nrows = [1, 2, 3]")
    print(s.run("print(sum(rows))").stdout)  # 6
```

## Results and errors

- A failure **inside** the sandbox is a normal result: `r.ok` is False, and `r.outcome` is `exit`, `limit`, `trap` or `error`. `r.exit_code`, `r.stderr`, `r.limits_hit` and `r.error` say why.
- `SandboxdError` is raised when the server refuses the request. Its `code` is the server's code (`UNAUTHORIZED`, `POLICY_NOT_FOUND`, `INVALID_REQUEST`, `SESSION_NOT_FOUND`, `SESSIONS_DISABLED`, ...) or `UNREACHABLE`, and `status` is the HTTP status.
- `429` answers (`OVERLOADED`, `SESSION_LIMIT`) are retried up to `retries` times (default 3), waiting as long as `Retry-After` says (at most 10 s).

## Options

`Sandboxd(url=None, token=None, *, timeout=300.0, retries=3, user_agent=None)`. `timeout` is the
socket timeout per request, in seconds; keep it above your longest `wall_clock` limit.

## Tests

```bash
python -m unittest discover -s clients/python/tests                       # unit tests only
python clients/testserver.py --sandboxd target/debug/sandboxd -- \
       python -m unittest discover -s clients/python/tests                # + a real server
```
