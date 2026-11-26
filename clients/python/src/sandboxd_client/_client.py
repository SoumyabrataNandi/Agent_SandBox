"""The sandboxd HTTP client (cycle 6, FR-CL1). Standard library only."""

from __future__ import annotations

import base64
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Iterator, Mapping, Optional, Sequence, Union

__version__ = "0.3.0"

DEFAULT_URL = "http://127.0.0.1:8080"
MAX_RETRY_WAIT_S = 10.0

FileContent = Union[str, bytes, bytearray, memoryview]
Files = Union[Mapping[str, FileContent], Sequence["tuple[str, FileContent]"]]
Limits = Mapping[str, str]


class SandboxdError(Exception):
    """The server refused a request (or could not be reached).

    `code` is the server's error code (`UNAUTHORIZED`, `POLICY_NOT_FOUND`, `OVERLOADED`,
    `INVALID_REQUEST`, `SESSION_NOT_FOUND`, ...), or `UNREACHABLE` when no response arrived.
    `status` is the HTTP status (None when unreachable).
    """

    def __init__(self, code: str, message: str, status: Optional[int] = None):
        super().__init__(f"{code}: {message}" if status is None else f"{code} ({status}): {message}")
        self.code = code
        self.message = message
        self.status = status


@dataclass(frozen=True)
class ErrorInfo:
    code: str
    message: str


@dataclass(frozen=True)
class Timings:
    queued_ms: int
    setup_ms: int
    run_ms: int
    collect_ms: int
    total_ms: int


@dataclass(frozen=True)
class Artifact:
    """A file the code wrote to /out."""

    name: str
    size: int
    sha256: str
    content: bytes

    def text(self, encoding: str = "utf-8") -> str:
        return self.content.decode(encoding)


@dataclass(frozen=True)
class RunResult:
    """The result of a run. `outcome` is ok | exit | limit | trap | error."""

    run_id: str
    language: str
    policy: str
    outcome: str
    exit_code: Optional[int]
    stdout: str
    stderr: str
    stdout_bytes: bytes
    stderr_bytes: bytes
    stdout_truncated: bool
    stderr_truncated: bool
    artifacts: "list[Artifact]"
    limits_hit: "list[str]"
    error: Optional[ErrorInfo]
    fuel_used: int
    peak_memory: int
    timings: Timings
    session_id: Optional[str] = None
    session_ended: Optional[str] = None
    raw: "dict[str, Any]" = field(default_factory=dict, repr=False, compare=False)

    @property
    def ok(self) -> bool:
        return self.outcome == "ok"

    def artifact(self, name: str) -> Artifact:
        for a in self.artifacts:
            if a.name == name:
                return a
        raise KeyError(name)

    @classmethod
    def from_json(cls, d: "dict[str, Any]") -> "RunResult":
        def raw_bytes(text_key: str, b64_key: str) -> bytes:
            b64 = d.get(b64_key)
            return base64.b64decode(b64) if b64 else (d.get(text_key) or "").encode("utf-8")

        err = d.get("error")
        t = d.get("timings") or {}
        return cls(
            run_id=d.get("run_id", ""),
            language=d.get("language", ""),
            policy=d.get("policy", ""),
            outcome=d.get("outcome", ""),
            exit_code=d.get("exit_code"),
            stdout=d.get("stdout", ""),
            stderr=d.get("stderr", ""),
            stdout_bytes=raw_bytes("stdout", "stdout_base64"),
            stderr_bytes=raw_bytes("stderr", "stderr_base64"),
            stdout_truncated=bool(d.get("stdout_truncated")),
            stderr_truncated=bool(d.get("stderr_truncated")),
            artifacts=[
                Artifact(a["name"], int(a["size"]), a["sha256"], base64.b64decode(a["content_base64"]))
                for a in d.get("artifacts") or []
            ],
            limits_hit=list(d.get("limits_hit") or []),
            error=ErrorInfo(err["code"], err["message"]) if err else None,
            fuel_used=int(d.get("fuel_used") or 0),
            peak_memory=int(d.get("peak_memory") or 0),
            timings=Timings(**{k: int(t.get(k) or 0) for k in
                               ("queued_ms", "setup_ms", "run_ms", "collect_ms", "total_ms")}),
            session_id=d.get("session_id"),
            session_ended=d.get("session_ended"),
            raw=d,
        )


@dataclass(frozen=True)
class StreamEvent:
    """One streaming event.

    `type` is `stdout` or `stderr` (`text`, plus `data` with the raw bytes), `limit` (`limit` names
    the limit that was hit), or `result` (`result` is the final RunResult; always the last event).
    """

    type: str
    text: Optional[str] = None
    data: Optional[bytes] = None
    limit: Optional[str] = None
    result: Optional[RunResult] = None


@dataclass(frozen=True)
class Policy:
    name: str
    description: str
    overrides_builtin: bool
    wall_clock: str
    memory: str
    mounts: "list[str]"


@dataclass(frozen=True)
class SessionInfo:
    session_id: str
    language: str
    policy: str
    interpreter: str
    state: str
    calls: int
    max_calls: int
    created_at: str
    expires_at: str
    idle_timeout_s: int
    ended_reason: Optional[str] = None

    @classmethod
    def from_json(cls, d: "dict[str, Any]") -> "SessionInfo":
        names = cls.__dataclass_fields__.keys()  # type: ignore[attr-defined]
        return cls(**{k: d[k] for k in names if k in d})


def _files(files: Optional[Files]) -> "list[dict[str, str]]":
    if not files:
        return []
    items = files.items() if isinstance(files, Mapping) else files
    out = []
    for name, content in items:
        if isinstance(content, str):
            out.append({"name": name, "content": content})
        else:
            out.append({"name": name, "content": base64.b64encode(bytes(content)).decode("ascii"),
                        "encoding": "base64"})
    return out


def _body(**kw: Any) -> "dict[str, Any]":
    return {k: v for k, v in kw.items() if v not in (None, [], {})}


class Session:
    """A persistent sandbox: variables, imports and files under /work carry over between runs.

    Use it as a context manager to close it at the end::

        with sbx.create_session(policy="notebook") as s:
            s.run("x = 41")
            print(s.run("print(x + 1)").stdout)
    """

    def __init__(self, client: "Sandboxd", session_id: str, info: Optional[SessionInfo] = None):
        self.client = client
        self.id = session_id
        self.last_info = info

    def __repr__(self) -> str:
        return f"Session({self.id!r})"

    def run(self, code: str, *, files: Optional[Files] = None, args: Optional[Sequence[str]] = None,
            limits: Optional[Limits] = None) -> RunResult:
        """Run one cell. `limits` may tighten `wall_clock` and `fuel` for this call only."""
        body = _body(code=code, files=_files(files), args=list(args or []), limits=dict(limits or {}))
        return RunResult.from_json(self.client._request("POST", f"/v1/sessions/{self._q()}/runs", body))

    def stream(self, code: str, *, files: Optional[Files] = None, args: Optional[Sequence[str]] = None,
               limits: Optional[Limits] = None) -> Iterator[StreamEvent]:
        """Run one cell, yielding output as it is produced; the last event is the result."""
        body = _body(code=code, files=_files(files), args=list(args or []), limits=dict(limits or {}))
        return self.client._stream(f"/v1/sessions/{self._q()}/runs", body)

    def info(self) -> SessionInfo:
        self.last_info = SessionInfo.from_json(self.client._request("GET", f"/v1/sessions/{self._q()}"))
        return self.last_info

    def close(self) -> SessionInfo:
        self.last_info = SessionInfo.from_json(self.client._request("DELETE", f"/v1/sessions/{self._q()}"))
        return self.last_info

    def __enter__(self) -> "Session":
        return self

    def __exit__(self, *exc: object) -> None:
        try:
            self.close()
        except SandboxdError as e:
            if e.code != "SESSION_NOT_FOUND":  # already ended (limit, idle timeout, ...)
                raise

    def _q(self) -> str:
        return urllib.parse.quote(self.id, safe="")


class Sandboxd:
    """A sandboxd server.

    `url` defaults to `$SANDBOXD_URL` (then http://127.0.0.1:8080), `token` to `$SANDBOXD_TOKEN`.
    `timeout` is the socket timeout in seconds for each request. Requests refused with 429
    (`OVERLOADED`, `SESSION_LIMIT`) are retried up to `retries` times, honouring `Retry-After`.
    """

    def __init__(self, url: Optional[str] = None, token: Optional[str] = None, *,
                 timeout: float = 300.0, retries: int = 3, user_agent: Optional[str] = None):
        self.url = (url or os.environ.get("SANDBOXD_URL") or DEFAULT_URL).rstrip("/")
        self._token = token if token is not None else os.environ.get("SANDBOXD_TOKEN") or None
        self.timeout = timeout
        self.retries = retries
        self.user_agent = user_agent or f"sandboxd-client-python/{__version__}"

    def __repr__(self) -> str:  # never show the token
        return f"Sandboxd({self.url!r})"

    # ---- API -------------------------------------------------------------------------------

    def run(self, code: str, language: str = "python", *, policy: Optional[str] = None,
            files: Optional[Files] = None, args: Optional[Sequence[str]] = None,
            stdin: Optional[str] = None, limits: Optional[Limits] = None) -> RunResult:
        """Run `code` in a fresh sandbox. Files appear read-only under /in; /out files come back
        as `result.artifacts`. `limits` (wall_clock, fuel, memory, stdout, stderr) can only
        tighten the policy."""
        body = self._run_body(code, language, policy, files, args, stdin, limits)
        return RunResult.from_json(self._request("POST", "/v1/runs", body))

    def stream(self, code: str, language: str = "python", *, policy: Optional[str] = None,
               files: Optional[Files] = None, args: Optional[Sequence[str]] = None,
               stdin: Optional[str] = None, limits: Optional[Limits] = None) -> Iterator[StreamEvent]:
        """Like `run`, but yields stdout/stderr/limit events as they happen; the last event has
        type `result`."""
        body = self._run_body(code, language, policy, files, args, stdin, limits)
        return self._stream("/v1/runs", body)

    def create_session(self, language: str = "python", *, policy: Optional[str] = None,
                       files: Optional[Files] = None, limits: Optional[Limits] = None) -> Session:
        """Start a persistent session. The policy must enable sessions."""
        body = _body(language=language, policy=policy, files=_files(files), limits=dict(limits or {}))
        info = SessionInfo.from_json(self._request("POST", "/v1/sessions", body))
        return Session(self, info.session_id, info)

    def session(self, session_id: str) -> Session:
        """Attach to an existing session by id."""
        return Session(self, session_id)

    def policies(self) -> "list[Policy]":
        rows = self._request("GET", "/v1/policies").get("policies") or []
        return [Policy(r["name"], r.get("description", ""), bool(r.get("overrides_builtin")),
                       r.get("wall_clock", ""), r.get("memory", ""), list(r.get("mounts") or []))
                for r in rows]

    def health(self) -> "dict[str, Any]":
        """`{"status": "ok"}` when ready; raises SandboxdError otherwise."""
        return self._request("GET", "/healthz")

    # ---- transport -------------------------------------------------------------------------

    @staticmethod
    def _run_body(code: str, language: str, policy: Optional[str], files: Optional[Files],
                  args: Optional[Sequence[str]], stdin: Optional[str],
                  limits: Optional[Limits]) -> "dict[str, Any]":
        return _body(language=language, code=code, policy=policy, files=_files(files),
                     args=list(args or []), stdin=stdin, limits=dict(limits or {}))

    def _open(self, method: str, path: str, body: Optional["dict[str, Any]"], accept: str):
        data = json.dumps(body).encode("utf-8") if body is not None else None
        headers = {"Accept": accept, "User-Agent": self.user_agent}
        if data is not None:
            headers["Content-Type"] = "application/json"
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        attempt = 0
        while True:
            req = urllib.request.Request(self.url + path, data=data, headers=headers, method=method)
            try:
                return urllib.request.urlopen(req, timeout=self.timeout)
            except urllib.error.HTTPError as e:
                err = _http_error(e)
                if e.code == 429 and attempt < self.retries:
                    attempt += 1
                    time.sleep(_retry_after(e.headers.get("Retry-After"), attempt))
                    continue
                raise err from None
            except urllib.error.URLError as e:
                raise SandboxdError("UNREACHABLE", f"{self.url}: {e.reason}") from None
            except OSError as e:  # timeouts, resets
                raise SandboxdError("UNREACHABLE", f"{self.url}: {e}") from None

    def _request(self, method: str, path: str, body: Optional["dict[str, Any]"] = None) -> "dict[str, Any]":
        with self._open(method, path, body, "application/json") as resp:
            raw = resp.read()
        return json.loads(raw) if raw else {}

    def _stream(self, path: str, body: "dict[str, Any]") -> Iterator[StreamEvent]:
        resp = self._open("POST", path + "?stream=true", body, "text/event-stream")
        return _events(resp)


def _http_error(e: urllib.error.HTTPError) -> SandboxdError:
    try:
        raw = e.read()
    except OSError:
        raw = b""
    try:
        err = json.loads(raw)["error"]
        return SandboxdError(str(err["code"]), str(err["message"]), e.code)
    except (ValueError, KeyError, TypeError):
        text = raw.decode("utf-8", "replace").strip() or e.reason or "request failed"
        return SandboxdError(f"HTTP_{e.code}", str(text), e.code)


def _retry_after(value: Optional[str], attempt: int) -> float:
    try:
        wait = float(value) if value else 0.5 * attempt
    except ValueError:
        wait = 0.5 * attempt
    return max(0.0, min(wait, MAX_RETRY_WAIT_S))


def _events(resp: Any) -> Iterator[StreamEvent]:
    """Parse server-sent events: `event:` + `data:` lines, a blank line ends an event."""
    with resp:
        name, data = "message", []
        for raw in resp:
            line = raw.decode("utf-8").rstrip("\r\n")
            if line:
                if line.startswith(":"):
                    continue  # keep-alive comment
                key, _, value = line.partition(":")
                value = value[1:] if value.startswith(" ") else value
                if key == "event":
                    name = value
                elif key == "data":
                    data.append(value)
                continue
            if data:
                ev = _event(name, json.loads("\n".join(data)))
                if ev is not None:
                    yield ev
                    if ev.type == "result":
                        return
            name, data = "message", []
    raise SandboxdError("STREAM_ENDED", "the stream ended without a result")


def _event(name: str, d: "dict[str, Any]") -> Optional[StreamEvent]:
    if name in ("stdout", "stderr"):
        b64 = d.get("base64")
        text = d.get("text", "")
        return StreamEvent(name, text=text, data=base64.b64decode(b64) if b64 else text.encode("utf-8"))
    if name == "limit":
        return StreamEvent("limit", limit=d.get("kind"))
    if name == "result":
        return StreamEvent("result", result=RunResult.from_json(d))
    if name == "error":
        err = d.get("error") or {}
        raise SandboxdError(str(err.get("code", "ERROR")), str(err.get("message", "")))
    return None  # unknown event types are ignored (forward compatibility)
