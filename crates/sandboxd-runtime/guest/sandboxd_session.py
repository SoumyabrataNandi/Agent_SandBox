"""sandboxd session loop (cycle 3, C3-U4).

Runs inside one live interpreter for the whole session. Each call arrives through the
``/dev/sandbox/session`` device: a read blocks (host-side) until the next call and returns
``{"cell": N, "path": "/code/cell_N.py", "args": [...]}``. The cell runs in the persistent
``__main__`` namespace; the loop then writes ``{"status": "ok"|"error"|"exit", "exit_code": n}``.
An empty read means the session is over.

* An uncaught exception prints CPython's traceback (without this loop's frames) and the session
  continues.
* ``sys.exit(n)`` ends the *call* with exit code n; the session continues.
* stdout/stderr are flushed before the result is reported, so output belongs to the right call.
"""

import os
import sys

_DEVICE = "/dev/sandbox/session"
_HELPERS = "/usr/local/lib/sandboxd"


def _exit_code(exc):
    code = exc.code
    if code is None:
        return 0
    if isinstance(code, int):
        return code
    print(code, file=sys.stderr)
    return 1


def _run_cell(path, ns):
    this = _run_cell.__code__.co_filename
    try:
        with open(path, "rb") as f:
            source = f.read()
        exec(compile(source, path, "exec", dont_inherit=True), ns)
    except SystemExit as exc:
        return "exit", _exit_code(exc)
    except BaseException as exc:
        tb = exc.__traceback__
        while tb is not None and tb.tb_frame.f_code.co_filename == this:
            tb = tb.tb_next
        exc.__traceback__ = tb  # the default hook prints exc.__traceback__
        sys.excepthook(type(exc), exc, tb)
        return "error", 1
    return "ok", 0


def _flush():
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.flush()
        except Exception:
            pass


def main(preloaded=False):
    """Serve calls until the host ends the session.

    ``preloaded`` is True on the snapshot path, where the network shims are already patched in;
    otherwise the same lazy patcher as one-shot runs is installed (C2-U3).
    """
    import json

    if not preloaded:
        if _HELPERS not in sys.path:
            sys.path.append(_HELPERS)
        import sandboxd_boot

        sandboxd_boot.install_patcher()
    main_module = type(sys)("__main__")
    main_module.__builtins__ = __builtins__
    sys.modules["__main__"] = main_module
    ns = main_module.__dict__
    fd = os.open(_DEVICE, os.O_RDWR)
    try:
        while True:
            data = os.read(fd, 1 << 16)
            if not data:
                break
            frame = json.loads(data)
            path = frame["path"]
            sys.argv = [path] + list(frame.get("args") or [])
            ns["__file__"] = path
            status, code = _run_cell(path, ns)
            _flush()
            os.write(fd, json.dumps({"status": status, "exit_code": code}).encode())
    finally:
        os.close(fd)
