"""Network access from inside the sandboxd WebAssembly sandbox (cycle 2, C2-U3).

The sandbox has no sockets. Every request goes through a host-side broker that enforces the
policy's allowlist, SSRF rules, quotas and timeouts, and writes the audit log. This module talks to
the broker through two virtual devices:

* ``/dev/sandbox/http``: one HTTP(S) exchange per open (length-prefixed JSON header + body);
* ``/dev/sandbox/tcp/<host>:<port>``: a raw byte stream.

Standard code works unchanged because the bootstrap patches, when they are first imported:

* ``http.client``: ``HTTPConnection`` and ``HTTPSConnection`` use the HTTP device (TLS is done by
  the broker); ``urllib.request`` therefore works too;
* ``socket.create_connection``: uses the TCP device.

Direct API::

    import sandbox_net
    r = sandbox_net.fetch("https://api.example.com/v1/items", headers={"Accept": "application/json"})
    print(r.status, r.json())

    with sandbox_net.connect("db.internal", 5432) as s:
        s.sendall(b"...")

Failures raise built-in exceptions (``PermissionError``, ``TimeoutError``, ``ConnectionError``,
``socket.gaierror``, ``OSError``) with a ``code`` attribute holding the broker's error code.
"""

import io
import os
import sys

__all__ = ["fetch", "connect", "Response", "Headers", "Connection"]

HTTP_DEVICE = "/dev/sandbox/http"
TCP_DEVICE = "/dev/sandbox/tcp/"
INFO_DEVICE = "/dev/sandbox/info"

_PROXY_REFUSED = (
    "proxies are not supported inside the sandbox; egress proxies are configured by the operator"
)

# --------------------------------------------------------------------------------------------
# Errors


def _error(cls, code, message):
    exc = cls(message)
    exc.code = code
    return exc


def _broker_error(code, message):
    if code in ("DENIED", "SSRF", "NETWORK_DISABLED"):
        cls = PermissionError
    elif code == "TIMEOUT":
        cls = TimeoutError
    elif code == "DNS":
        import socket

        cls = socket.gaierror
    elif code in ("CONNECT", "TLS"):
        cls = ConnectionError
    else:
        cls = OSError
    return _error(cls, code, message or code or "network error")


_info_cache = None


def _info():
    global _info_cache
    if _info_cache is None:
        import json

        try:
            fd = os.open(INFO_DEVICE, os.O_RDONLY)
            try:
                _info_cache = json.loads(_read_all(fd))
            finally:
                os.close(fd)
        except (OSError, ValueError):
            _info_cache = {"policy": "?", "http": False, "tcp": False}
    return _info_cache


def _not_allowed(kind):
    info = _info()
    policy = info.get("policy", "?")
    if not info.get("http") and not info.get("tcp"):
        msg = "network access is not allowed by policy %r" % (policy,)
    elif kind == "http":
        msg = "HTTP requests are not allowed by policy %r (it grants raw TCP only)" % (policy,)
    else:
        msg = "raw TCP connections are not allowed by policy %r (it grants HTTP only)" % (policy,)
    return _error(PermissionError, "NETWORK_DISABLED", msg)


# --------------------------------------------------------------------------------------------
# Device I/O


def _read_all(fd):
    chunks = []
    while True:
        chunk = os.read(fd, 1 << 16)
        if not chunk:
            break
        chunks.append(chunk)
    return b"".join(chunks)


def _write_all(fd, data):
    view = memoryview(data)
    while view:
        n = os.write(fd, view)
        view = view[n:]


def _to_bytes(body):
    if body is None:
        return b""
    if isinstance(body, str):
        return body.encode("utf-8")
    if isinstance(body, (bytes, bytearray, memoryview)):
        return bytes(body)
    if hasattr(body, "read"):
        data = body.read()
        return data.encode("utf-8") if isinstance(data, str) else bytes(data)
    return b"".join(
        part.encode("utf-8") if isinstance(part, str) else bytes(part) for part in body
    )


def _header_pairs(headers):
    if headers is None:
        return []
    items = headers.items() if hasattr(headers, "items") else headers
    pairs = []
    for name, value in items:
        if isinstance(name, bytes):
            name = name.decode("latin-1")
        if isinstance(value, bytes):
            value = value.decode("latin-1")
        pairs.append([str(name), str(value)])
    return pairs


def _exchange(method, url, headers, body, timeout):
    """One request through the broker. Returns (response header dict, body bytes)."""
    import json

    header = {
        "method": str(method).upper(),
        "url": str(url),
        "headers": headers,
        "body_len": len(body),
    }
    if timeout is not None:
        header["timeout_ms"] = max(1, int(float(timeout) * 1000))
    raw = json.dumps(header, separators=(",", ":")).encode("utf-8")
    frame = len(raw).to_bytes(4, "little") + raw + body
    try:
        fd = os.open(HTTP_DEVICE, os.O_RDWR)
    except FileNotFoundError:
        raise _not_allowed("http") from None
    try:
        try:
            _write_all(fd, frame)
        except OSError as exc:
            raise _error(
                OSError, "QUOTA", "request is larger than the policy's max_request_bytes"
            ) from exc
        data = _read_all(fd)
    finally:
        os.close(fd)
    if len(data) < 4:
        raise _error(OSError, "PROTOCOL", "malformed response from the network broker")
    n = int.from_bytes(data[:4], "little")
    meta = json.loads(data[4 : 4 + n])
    err = meta.get("error")
    if err:
        raise _broker_error(err.get("code"), err.get("message"))
    return meta, data[4 + n :]


# --------------------------------------------------------------------------------------------
# fetch()


class Headers:
    """Case-insensitive, multi-valued response headers."""

    def __init__(self, pairs=()):
        self._items = [(str(k), str(v)) for k, v in pairs]

    def get(self, name, default=None):
        values = self.get_all(name)
        return ", ".join(values) if values else default

    def get_all(self, name):
        key = name.lower()
        return [v for k, v in self._items if k.lower() == key]

    def __getitem__(self, name):
        value = self.get(name)
        if value is None:
            raise KeyError(name)
        return value

    def __contains__(self, name):
        return bool(self.get_all(name))

    def __iter__(self):
        return iter(self.keys())

    def __len__(self):
        return len(self.keys())

    def keys(self):
        seen, out = set(), []
        for k, _ in self._items:
            if k.lower() not in seen:
                seen.add(k.lower())
                out.append(k)
        return out

    def items(self):
        return list(self._items)

    def __repr__(self):
        return "Headers(%r)" % (self._items,)


class Response:
    """Result of :func:`fetch`. HTTP error statuses are returned, not raised."""

    def __init__(self, status, headers, body, url, redirects=0):
        self.status = status
        self.headers = headers
        self.body = body
        self.url = url
        self.redirects = redirects

    @property
    def ok(self):
        return 200 <= self.status < 300

    @property
    def reason(self):
        from http import HTTPStatus

        try:
            return HTTPStatus(self.status).phrase
        except ValueError:
            return ""

    def text(self, encoding=None):
        if encoding is None:
            encoding = "utf-8"
            ctype = self.headers.get("content-type", "")
            for part in ctype.split(";")[1:]:
                key, _, value = part.strip().partition("=")
                if key.lower() == "charset" and value:
                    encoding = value.strip("\"'")
        return self.body.decode(encoding, "replace")

    def json(self):
        import json

        return json.loads(self.body)

    def raise_for_status(self):
        if self.status >= 400:
            raise _error(OSError, "HTTP_%d" % self.status, "HTTP %d for %s" % (self.status, self.url))
        return self

    def __repr__(self):
        return "<Response [%d] %s>" % (self.status, self.url)


def fetch(url, method="GET", headers=None, body=None, timeout=None):
    """Perform one HTTP(S) request through the broker and return a :class:`Response`.

    Redirects are followed by the broker (each hop is checked against the policy).
    """
    meta, data = _exchange(method, url, _header_pairs(headers), _to_bytes(body), timeout)
    return Response(
        meta.get("status", 0),
        Headers(meta.get("headers", [])),
        data,
        meta.get("url") or url,
        meta.get("redirects", 0),
    )


# --------------------------------------------------------------------------------------------
# connect(): raw TCP


def _tcp_io_error(exc, host, port):
    import errno

    where = "%s:%s" % (host, port)
    if exc.errno == errno.ETIMEDOUT:
        return _error(TimeoutError, "TIMEOUT", "connection to %s timed out" % where)
    if exc.errno == errno.EIO:
        return _error(OSError, "QUOTA", "network byte quota exhausted")
    if exc.errno == errno.EPIPE:
        return _error(BrokenPipeError, "CONNECT", "connection to %s was closed" % where)
    return _error(ConnectionResetError, "CONNECT", "connection to %s was reset" % where)


class _ConnectionIO(io.RawIOBase):
    def __init__(self, conn, mode):
        io.RawIOBase.__init__(self)
        self._conn = conn
        self._reading = "r" in mode
        self._writing = "w" in mode

    def readable(self):
        return self._reading

    def writable(self):
        return self._writing

    def readinto(self, b):
        return self._conn.recv_into(b)

    def write(self, b):
        return self._conn.send(b)


class Connection:
    """A socket-like TCP stream through the broker (see :func:`connect`)."""

    def __init__(self, fd, host, port, timeout):
        self._fd = fd
        self._host = host
        self._port = port
        self._timeout = timeout

    def _live(self):
        if self._fd is None:
            raise _error(OSError, "CLOSED", "connection is closed")
        return self._fd

    @property
    def family(self):
        import socket

        return socket.AF_INET6 if ":" in self._host else socket.AF_INET

    @property
    def type(self):
        import socket

        return socket.SOCK_STREAM

    def fileno(self):
        return -1

    def send(self, data, flags=0):
        try:
            return os.write(self._live(), data)
        except OSError as exc:
            if getattr(exc, "code", None):
                raise
            raise _tcp_io_error(exc, self._host, self._port) from None

    def sendall(self, data, flags=0):
        view = memoryview(data).cast("B")
        while view:
            n = self.send(view)
            view = view[n:]

    def recv(self, bufsize, flags=0):
        if bufsize <= 0:
            return b""
        try:
            return os.read(self._live(), bufsize)
        except OSError as exc:
            if getattr(exc, "code", None):
                raise
            raise _tcp_io_error(exc, self._host, self._port) from None

    def recv_into(self, buffer, nbytes=0, flags=0):
        view = memoryview(buffer).cast("B")
        data = self.recv(nbytes or len(view))
        view[: len(data)] = data
        return len(data)

    def makefile(self, mode="r", buffering=None, *, encoding=None, errors=None, newline=None):
        if not set(mode) <= {"r", "w", "b"}:
            raise ValueError("invalid mode %r (only r, w, b allowed)" % (mode,))
        reading, writing, binary = "r" in mode, "w" in mode, "b" in mode
        if not reading and not writing:
            reading = True
        raw = _ConnectionIO(self, ("r" if reading else "") + ("w" if writing else ""))
        if buffering is None or buffering < 0:
            buffering = io.DEFAULT_BUFFER_SIZE
        if buffering == 0:
            if not binary:
                raise ValueError("unbuffered streams must be binary")
            return raw
        if reading and writing:
            buf = io.BufferedRWPair(raw, raw, buffering)
        elif reading:
            buf = io.BufferedReader(raw, buffering)
        else:
            buf = io.BufferedWriter(raw, buffering)
        if binary:
            return buf
        return io.TextIOWrapper(buf, encoding, errors, newline)

    def close(self):
        fd, self._fd = self._fd, None
        if fd is not None:
            os.close(fd)

    def shutdown(self, how):
        # Half-close isn't supported by the broker; a full shutdown closes the stream.
        if how == 2:
            self.close()

    def settimeout(self, value):
        self._timeout = value

    def gettimeout(self):
        return self._timeout

    def setblocking(self, flag):
        if not flag:
            raise _error(OSError, "UNSUPPORTED", "non-blocking sockets are not supported in the sandbox")

    def setsockopt(self, *args):
        return None

    def getsockopt(self, *args):
        return 0

    def getpeername(self):
        return (self._host, self._port)

    def getsockname(self):
        return ("0.0.0.0", 0)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass

    def __repr__(self):
        state = "closed" if self._fd is None else "open"
        return "<sandbox_net.Connection %s:%s %s>" % (self._host, self._port, state)


def connect(host, port, timeout=None):
    """Open a TCP stream to ``host:port`` through the broker (needs a ``tcp`` policy rule)."""
    host = str(host)
    port = int(port)
    if not host or "/" in host or "\0" in host:
        raise _error(ValueError, "PROTOCOL", "invalid host %r" % (host,))
    spec = "[%s]:%d" % (host, port) if ":" in host else "%s:%d" % (host, port)
    where = "%s:%d" % (host, port)
    try:
        fd = os.open(TCP_DEVICE + spec, os.O_RDWR)
    except FileNotFoundError:
        if not _info().get("tcp"):
            raise _not_allowed("tcp") from None
        import socket

        raise _error(socket.gaierror, "DNS", "could not resolve %s" % (host,)) from None
    except PermissionError:
        raise _error(
            PermissionError,
            "DENIED",
            "connection to %s is not allowed by the sandbox network policy (see the audit log)"
            % where,
        ) from None
    except ConnectionRefusedError:
        raise _error(ConnectionRefusedError, "CONNECT", "connection to %s was refused" % where) from None
    except TimeoutError:
        raise _error(TimeoutError, "TIMEOUT", "connection to %s timed out" % where) from None
    except OSError as exc:
        raise _error(ConnectionError, "CONNECT", "connection to %s failed: %s" % (where, exc.strerror)) from None
    return Connection(fd, host, port, timeout)


# --------------------------------------------------------------------------------------------
# http.client: HTTP over the device


def _decode_chunked(data):
    out = bytearray()
    while True:
        line, sep, data = data.partition(b"\r\n")
        if not sep:
            break
        size = int(line.split(b";", 1)[0].strip() or b"0", 16)
        if size == 0:
            break
        out += data[:size]
        data = data[size + 2 :]
    return bytes(out)


class _DeviceSocket:
    """Stands in for http.client's socket: buffers the request, exchanges it on `makefile`."""

    def __init__(self, conn):
        self._conn = conn
        self._buf = bytearray()
        self._response = None

    def _prepare(self):
        """Run the exchange (called before http.client builds its response object)."""
        if self._response is None and self._buf:
            self._response = self._exchange()

    def sendall(self, data):
        self._buf += data

    def send(self, data):
        self._buf += data
        return len(data)

    def setsockopt(self, *args):
        return None

    def settimeout(self, value):
        return None

    def close(self):
        self._buf = bytearray()

    def makefile(self, mode="rb", *args, **kwargs):
        self._prepare()
        data, self._response = self._response or b"", None
        return io.BytesIO(data)

    def _exchange(self):
        conn = self._conn
        data = bytes(self._buf)
        self._buf = bytearray()
        head, sep, rest = data.partition(b"\r\n\r\n")
        if not sep:
            raise _error(OSError, "PROTOCOL", "incomplete HTTP request")
        lines = head.decode("latin-1").split("\r\n")
        try:
            method, target, _version = lines[0].split(" ", 2)
        except ValueError:
            raise _error(OSError, "PROTOCOL", "malformed HTTP request line") from None
        if not target.startswith("/"):
            raise _error(PermissionError, "DENIED", _PROXY_REFUSED)
        headers, length, chunked = [], None, False
        for line in lines[1:]:
            name, _, value = line.partition(":")
            name, value = name.strip(), value.strip()
            lower = name.lower()
            if lower == "content-length":
                length = int(value)
            elif lower == "transfer-encoding":
                chunked = "chunked" in value.lower()
            elif lower != "host":
                headers.append([name, value])
        if chunked:
            body = _decode_chunked(rest)
        elif length is not None:
            body = rest[:length]
        else:
            body = rest
        scheme = getattr(conn, "_sandboxd_scheme", "http")
        host = "[%s]" % conn.host if ":" in conn.host else conn.host
        default = 443 if scheme == "https" else 80
        port = "" if conn.port == default else ":%d" % conn.port
        url = "%s://%s%s%s" % (scheme, host, port, target)
        timeout = conn.timeout if isinstance(conn.timeout, (int, float)) else None
        meta, payload = _exchange(method, url, headers, body, timeout)
        conn._sandboxd_url = meta.get("url") or url
        return _synthesize(meta, payload, method)


def _synthesize(meta, payload, method):
    import http.client

    status = int(meta.get("status", 0))
    reason = http.client.responses.get(status, "")
    out = [("HTTP/1.1 %d %s\r\n" % (status, reason)).encode("latin-1")]
    for name, value in meta.get("headers", []):
        if name.lower() in ("content-length", "transfer-encoding", "connection", "keep-alive"):
            continue
        out.append(("%s: %s\r\n" % (name, value)).encode("latin-1", "replace"))
    if method.upper() == "HEAD":
        payload = b""
    out.append(b"Content-Length: %d\r\nConnection: close\r\n\r\n" % len(payload))
    out.append(payload)
    return b"".join(out)


class _BrokerTLSContext:
    """Placeholder for ``ssl.SSLContext``: TLS is negotiated and verified by the host broker."""

    check_hostname = True
    verify_mode = 2
    post_handshake_auth = None

    def set_alpn_protocols(self, protocols):
        return None

    def load_verify_locations(self, *args, **kwargs):
        return None

    def load_cert_chain(self, *args, **kwargs):
        return None


def _patch_http_client(hc):
    base = hc.HTTPConnection
    if getattr(base, "_sandboxd", False):
        return
    original_getresponse = base.getresponse

    def connect(self):
        sys.audit("http.client.connect", self, self.host, self.port)
        if getattr(self, "_tunnel_host", None):
            raise _error(PermissionError, "DENIED", _PROXY_REFUSED)
        self.sock = _DeviceSocket(self)

    def set_tunnel(self, host, port=None, headers=None):
        raise _error(PermissionError, "DENIED", _PROXY_REFUSED)

    def getresponse(self):
        try:
            if isinstance(self.sock, _DeviceSocket):
                # Exchange first, so a failure never leaves a half-built HTTPResponse behind.
                self.sock._prepare()
            response = original_getresponse(self)
        except BaseException:
            # The exchange failed before a response existed: reset the connection state so the
            # same object can send another request (as after a failed real connection).
            self.close()
            raise
        response._sandboxd_url = getattr(self, "_sandboxd_url", None)
        return response

    base.connect = connect
    base.set_tunnel = set_tunnel
    base.getresponse = getresponse
    base._sandboxd = True
    base._sandboxd_scheme = "http"

    class HTTPSConnection(base):
        """HTTPS through the sandbox broker (which does TLS with the OS trust store)."""

        default_port = hc.HTTPS_PORT
        _sandboxd_scheme = "https"

        def __init__(self, host, port=None, *args, context=None, check_hostname=None, **kwargs):
            kwargs.pop("key_file", None)
            kwargs.pop("cert_file", None)
            super().__init__(host, port, *args, **kwargs)
            self._context = context

    HTTPSConnection.__module__ = "http.client"
    hc.HTTPSConnection = HTTPSConnection
    hc._create_https_context = lambda http_version: _BrokerTLSContext()
    if "HTTPSConnection" not in hc.__all__:
        hc.__all__.append("HTTPSConnection")


def _patch_urllib_request(ur):
    import urllib.error

    handler = ur.AbstractHTTPHandler
    original_do_open = handler.do_open

    def do_open(self, http_class, req, **http_conn_args):
        try:
            response = original_do_open(self, http_class, req, **http_conn_args)
        except urllib.error.URLError:
            raise
        except OSError as err:
            raise urllib.error.URLError(err)
        final = getattr(response, "_sandboxd_url", None)
        if final:
            response.url = final
        return response

    handler.do_open = do_open


def _patch_socket(sock):
    default = sock._GLOBAL_DEFAULT_TIMEOUT

    def create_connection(address, timeout=default, source_address=None, *, all_errors=False):
        """Connect to ``address`` through the sandbox broker (needs a ``tcp`` policy rule)."""
        host, port = address[0], address[1]
        return connect(host, port, timeout if isinstance(timeout, (int, float)) else None)

    sock.create_connection = create_connection


def _install(name, module):
    """Called by the bootstrap right after ``module`` has been loaded."""
    if name == "http.client":
        _patch_http_client(module)
    elif name == "urllib.request":
        _patch_urllib_request(module)
    elif name == "socket":
        _patch_socket(module)
