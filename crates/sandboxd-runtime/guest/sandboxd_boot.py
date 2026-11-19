"""sandboxd Python bootstrap (cycle 2, C2-U3).

Launched as::

    python -I -B -S -X frozen_modules=on -c "<launcher>" /code/main.py <args>

where the one-line launcher puts ``/usr/local/lib/sandboxd`` on ``sys.path`` and calls
``sandboxd_boot.main()``. This module and ``sandbox_net`` are precompiled to ``__pycache__`` when
the runtime starts, so a run never compiles the bootstrap from source (NFR-N3).

``main()`` runs ``/code/main.py`` as ``__main__`` so that ``sys.argv``, tracebacks and exit codes
are the same as when CPython runs the file directly, and installs the network shims from
``sandbox_net`` *lazily*: nothing is imported until the program itself imports ``http.client``,
``urllib.request`` or ``socket``.

This module imports only ``sys``. No security decision is made here: every request is enforced by
the host-side broker.
"""

import sys

_HELPERS = "/usr/local/lib/sandboxd"
_TARGETS = ("http.client", "socket", "urllib.request")


class _PatchingLoader:
    """Runs the real loader, then applies the sandbox patch for that module."""

    def __init__(self, loader, name):
        self._loader = loader
        self._name = name

    def create_module(self, spec):
        return self._loader.create_module(spec)

    def exec_module(self, module):
        self._loader.exec_module(module)
        import sandbox_net

        sandbox_net._install(self._name, module)

    def __getattr__(self, attr):
        return getattr(self._loader, attr)


class _LazyPatcher:
    """A meta-path finder that only reacts to the modules it patches."""

    def __init__(self):
        self.pending = set(_TARGETS)

    def find_spec(self, name, path=None, target=None):
        if name not in self.pending:
            return None
        spec = None
        for finder in sys.meta_path:
            if finder is self:
                continue
            find = getattr(finder, "find_spec", None)
            if find is None:
                continue
            spec = find(name, path, target)
            if spec is not None:
                break
        if spec is None or spec.loader is None or not hasattr(spec.loader, "exec_module"):
            return spec
        self.pending.discard(name)
        if not self.pending and self in sys.meta_path:
            sys.meta_path.remove(self)
        spec.loader = _PatchingLoader(spec.loader, name)
        return spec


def _run():
    # ['-c', '/code/main.py', *args] → ['/code/main.py', *args], exactly as in cycle 1.
    sys.argv = sys.argv[1:]
    path = sys.argv[0]
    sys.path.append(_HELPERS)  # `import sandbox_net` works; /code stays off sys.path
    sys.meta_path.insert(0, _LazyPatcher())
    with open(path, "rb") as f:
        source = f.read()
    code = compile(source, path, "exec", dont_inherit=True)
    main = type(sys)("__main__")
    main.__file__ = path
    main.__builtins__ = __builtins__
    sys.modules["__main__"] = main
    exec(code, main.__dict__)


def main():
    """Run the program; on an uncaught exception print it without bootstrap frames, exit 1."""
    this = main.__code__.co_filename
    try:
        _run()
    except SystemExit:
        raise
    except BaseException as exc:
        tb = exc.__traceback__
        while tb is not None and tb.tb_frame.f_code.co_filename == this:
            tb = tb.tb_next
        # The default hook prints `exc.__traceback__` (it ignores its tb argument since 3.12),
        # so the trimmed traceback goes on the exception itself.
        exc.__traceback__ = tb
        sys.excepthook(type(exc), exc, tb)
        failed = True
    else:
        failed = False
    if failed:
        raise SystemExit(1)
