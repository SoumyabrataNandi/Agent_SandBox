"""Python client for the sandboxd HTTP API.

    from sandboxd_client import Sandboxd

    sbx = Sandboxd()  # SANDBOXD_URL / SANDBOXD_TOKEN, or Sandboxd(url, token)
    r = sbx.run("print(6*7)")
    print(r.stdout)  # 42

Standard library only. A guest failure (an exception, a non-zero exit, a limit) is a normal
result (`r.ok` is False); `SandboxdError` is raised only when the server refuses a request.
"""

from ._client import (
    Artifact,
    ErrorInfo,
    Policy,
    RunResult,
    Sandboxd,
    SandboxdError,
    Session,
    SessionInfo,
    StreamEvent,
    Timings,
    __version__,
)

__all__ = [
    "Artifact",
    "ErrorInfo",
    "Policy",
    "RunResult",
    "Sandboxd",
    "SandboxdError",
    "Session",
    "SessionInfo",
    "StreamEvent",
    "Timings",
    "__version__",
]
