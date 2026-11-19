// sandboxd `fetch` implementation (cycle 2, C2-U3), loaded lazily by boot.js on first use of
// `fetch`, `Headers` or `Response`. This file is one function expression: boot.js evaluates it and
// calls it with the `qjs:os` module; it returns `{ fetch, Headers, Response }`.
//
// `fetch` is WHATWG-style and runs over the sandbox's HTTP device `/dev/sandbox/http`. The
// host-side broker enforces the policy (allowlist, SSRF rules, quotas, timeouts), does TLS,
// follows redirects and writes the audit log; no security decision is made here. A request blocks
// the (single) guest thread while it runs.

(function sandboxdFetch(os) {
'use strict';

const HTTP_DEVICE = '/dev/sandbox/http';
const INFO_DEVICE = '/dev/sandbox/info';
const ENOENT = 44; // WASI errno

// ---------------------------------------------------------------------------------------------
// UTF-8 (QuickJS has no TextEncoder/TextDecoder)

function utf8Encode(str) {
  const out = [];
  for (let i = 0; i < str.length; i++) {
    let c = str.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff && i + 1 < str.length) {
      const d = str.charCodeAt(i + 1);
      if (d >= 0xdc00 && d <= 0xdfff) {
        c = 0x10000 + ((c - 0xd800) << 10) + (d - 0xdc00);
        i++;
      } else {
        c = 0xfffd;
      }
    } else if (c >= 0xd800 && c <= 0xdfff) {
      c = 0xfffd;
    }
    if (c < 0x80) out.push(c);
    else if (c < 0x800) out.push(0xc0 | (c >> 6), 0x80 | (c & 63));
    else if (c < 0x10000) out.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 63), 0x80 | (c & 63));
    else out.push(0xf0 | (c >> 18), 0x80 | ((c >> 12) & 63), 0x80 | ((c >> 6) & 63), 0x80 | (c & 63));
  }
  return new Uint8Array(out);
}

function utf8Decode(bytes) {
  let s = '';
  const cps = [];
  const flush = () => {
    s += String.fromCodePoint(...cps);
    cps.length = 0;
  };
  for (let i = 0; i < bytes.length; ) {
    const b = bytes[i];
    let need = 0;
    let cp = 0;
    let min = 0;
    if (b < 0x80) {
      cp = b;
    } else if (b >= 0xc2 && b <= 0xdf) {
      need = 1; cp = b & 0x1f; min = 0x80;
    } else if (b >= 0xe0 && b <= 0xef) {
      need = 2; cp = b & 0x0f; min = 0x800;
    } else if (b >= 0xf0 && b <= 0xf4) {
      need = 3; cp = b & 0x07; min = 0x10000;
    } else {
      cps.push(0xfffd); i++;
      if (cps.length >= 4096) flush();
      continue;
    }
    let j = 1;
    for (; j <= need; j++) {
      const c = bytes[i + j];
      if (c === undefined || (c & 0xc0) !== 0x80) break;
      cp = (cp << 6) | (c & 0x3f);
    }
    if (j <= need || cp < min || cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff)) {
      cps.push(0xfffd);
      i += Math.max(1, j);
    } else {
      cps.push(cp);
      i += need + 1;
    }
    if (cps.length >= 4096) flush();
  }
  flush();
  return s;
}

// ---------------------------------------------------------------------------------------------
// Device I/O

function readAll(fd) {
  const chunks = [];
  let total = 0;
  const buf = new ArrayBuffer(65536);
  for (;;) {
    const n = os.read(fd, buf, 0, buf.byteLength);
    if (n < 0) throw new TypeError(`fetch failed: device read error (errno ${-n})`);
    if (n === 0) break;
    chunks.push(new Uint8Array(buf.slice(0, n)));
    total += n;
  }
  const out = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    out.set(c, off);
    off += c.length;
  }
  return out;
}

function writeAll(fd, bytes) {
  let off = 0;
  while (off < bytes.length) {
    const n = os.write(fd, bytes.buffer, bytes.byteOffset + off, bytes.length - off);
    if (n < 0) {
      throw new TypeError("fetch failed: request is larger than the policy's max_request_bytes", {
        cause: { code: 'QUOTA', message: 'request too large' },
      });
    }
    off += n;
  }
}

let infoCache = null;
function info() {
  if (infoCache === null) {
    infoCache = { policy: '?', http: false, tcp: false };
    const fd = os.open(INFO_DEVICE, os.O_RDONLY);
    if (fd >= 0) {
      try {
        infoCache = JSON.parse(utf8Decode(readAll(fd)));
      } catch (_) {
        // keep the default
      } finally {
        os.close(fd);
      }
    }
  }
  return infoCache;
}

function notAllowed() {
  const i = info();
  const message = i.tcp
    ? `HTTP requests are not allowed by policy '${i.policy}' (it grants raw TCP only)`
    : `network access is not allowed by policy '${i.policy}'`;
  return new TypeError(message, { cause: { code: 'NETWORK_DISABLED', message } });
}

// ---------------------------------------------------------------------------------------------
// Headers

function normName(name) {
  const n = String(name);
  if (!/^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/.test(n)) throw new TypeError(`invalid header name: ${n}`);
  return n.toLowerCase();
}

function normValue(value) {
  const v = String(value).replace(/^[\t\n\r ]+|[\t\n\r ]+$/g, '');
  if (/[\r\n\0]/.test(v)) throw new TypeError('invalid header value');
  return v;
}

class Headers {
  #list = []; // [lowercase name, value]

  constructor(init) {
    if (init === undefined || init === null) return;
    if (init instanceof Headers) {
      for (const [k, v] of init.#list) this.#list.push([k, v]);
    } else if (typeof init[Symbol.iterator] === 'function') {
      for (const pair of init) {
        const p = Array.from(pair);
        if (p.length !== 2) throw new TypeError('header pairs must have exactly two items');
        this.append(p[0], p[1]);
      }
    } else if (typeof init === 'object') {
      for (const k of Object.keys(init)) this.append(k, init[k]);
    } else {
      throw new TypeError('invalid headers init');
    }
  }

  append(name, value) {
    this.#list.push([normName(name), normValue(value)]);
  }

  set(name, value) {
    const n = normName(name);
    const v = normValue(value);
    const i = this.#list.findIndex(([k]) => k === n);
    if (i < 0) {
      this.#list.push([n, v]);
      return;
    }
    this.#list[i][1] = v;
    this.#list = this.#list.filter(([k], j) => k !== n || j === i);
  }

  get(name) {
    const n = normName(name);
    const vals = this.#list.filter(([k]) => k === n).map(([, v]) => v);
    return vals.length ? vals.join(', ') : null;
  }

  getSetCookie() {
    return this.#list.filter(([k]) => k === 'set-cookie').map(([, v]) => v);
  }

  has(name) {
    const n = normName(name);
    return this.#list.some(([k]) => k === n);
  }

  delete(name) {
    const n = normName(name);
    this.#list = this.#list.filter(([k]) => k !== n);
  }

  *entries() {
    const names = [...new Set(this.#list.map(([k]) => k))].sort();
    for (const n of names) {
      if (n === 'set-cookie') for (const v of this.getSetCookie()) yield [n, v];
      else yield [n, this.get(n)];
    }
  }

  *keys() {
    for (const [k] of this.entries()) yield k;
  }

  *values() {
    for (const [, v] of this.entries()) yield v;
  }

  forEach(callback, thisArg) {
    for (const [k, v] of this.entries()) callback.call(thisArg, v, k, this);
  }

  [Symbol.iterator]() {
    return this.entries();
  }

  get [Symbol.toStringTag]() {
    return 'Headers';
  }

  /** @internal raw pairs for the broker frame */
  _pairs() {
    return this.#list.map(([k, v]) => [k, v]);
  }
}

// ---------------------------------------------------------------------------------------------
// Response

const STATUS_TEXT = {
  200: 'OK', 201: 'Created', 202: 'Accepted', 204: 'No Content', 206: 'Partial Content',
  301: 'Moved Permanently', 302: 'Found', 303: 'See Other', 304: 'Not Modified',
  307: 'Temporary Redirect', 308: 'Permanent Redirect', 400: 'Bad Request',
  401: 'Unauthorized', 403: 'Forbidden', 404: 'Not Found', 405: 'Method Not Allowed',
  409: 'Conflict', 410: 'Gone', 413: 'Content Too Large', 415: 'Unsupported Media Type',
  422: 'Unprocessable Content', 429: 'Too Many Requests', 500: 'Internal Server Error',
  501: 'Not Implemented', 502: 'Bad Gateway', 503: 'Service Unavailable', 504: 'Gateway Timeout',
};

function toBytes(body) {
  if (body === undefined || body === null) return new Uint8Array(0);
  if (typeof body === 'string') return utf8Encode(body);
  if (body instanceof ArrayBuffer) return new Uint8Array(body.slice(0));
  if (ArrayBuffer.isView(body)) {
    return new Uint8Array(body.buffer.slice(body.byteOffset, body.byteOffset + body.byteLength));
  }
  return utf8Encode(String(body));
}

class Response {
  #body;
  #used = false;
  #url = '';
  #redirected = false;

  constructor(body = null, init = {}) {
    this.#body = toBytes(body);
    this.status = init.status ?? 200;
    this.statusText = init.statusText ?? STATUS_TEXT[this.status] ?? '';
    this.headers = init.headers instanceof Headers ? init.headers : new Headers(init.headers);
    if (typeof body === 'string' && !this.headers.has('content-type')) {
      this.headers.set('content-type', 'text/plain;charset=UTF-8');
    }
  }

  get ok() {
    return this.status >= 200 && this.status < 300;
  }

  get url() {
    return this.#url;
  }

  get redirected() {
    return this.#redirected;
  }

  get bodyUsed() {
    return this.#used;
  }

  get type() {
    return 'basic';
  }

  #consume() {
    if (this.#used) return Promise.reject(new TypeError('body has already been consumed'));
    this.#used = true;
    return Promise.resolve(this.#body);
  }

  bytes() {
    return this.#consume().then((b) => new Uint8Array(b));
  }

  arrayBuffer() {
    return this.#consume().then((b) => b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength));
  }

  text() {
    return this.#consume().then(utf8Decode);
  }

  json() {
    return this.text().then((t) => JSON.parse(t));
  }

  clone() {
    if (this.#used) throw new TypeError('body has already been consumed');
    const r = new Response(this.#body, {
      status: this.status,
      statusText: this.statusText,
      headers: new Headers(this.headers),
    });
    r.#url = this.#url;
    r.#redirected = this.#redirected;
    return r;
  }

  get [Symbol.toStringTag]() {
    return 'Response';
  }

  static _fromBroker(body, meta) {
    const r = new Response(body, {
      status: meta.status,
      headers: new Headers(meta.headers || []),
    });
    r.#url = meta.url || '';
    r.#redirected = (meta.redirects || 0) > 0;
    return r;
  }
}

// ---------------------------------------------------------------------------------------------
// fetch

function doFetch(input, init) {
  init = init ?? {};
  const isObj = input !== null && typeof input === 'object';
  const url = typeof input === 'string' ? input : isObj && typeof input.url === 'string' ? input.url : String(input);
  const method = String(init.method ?? (isObj ? input.method : undefined) ?? 'GET').toUpperCase();
  const headers = new Headers(init.headers ?? (isObj ? input.headers : undefined));
  if (init.redirect !== undefined && init.redirect !== 'follow') {
    throw new TypeError("only redirect: 'follow' is supported in the sandbox");
  }
  const rawBody = init.body;
  if (rawBody !== undefined && rawBody !== null && (method === 'GET' || method === 'HEAD')) {
    throw new TypeError(`a ${method} request cannot have a body`);
  }
  if (typeof rawBody === 'string' && !headers.has('content-type')) {
    headers.set('content-type', 'text/plain;charset=UTF-8');
  }
  const body = toBytes(rawBody);

  const header = utf8Encode(
    JSON.stringify({ method, url, headers: headers._pairs(), body_len: body.length }),
  );
  const frame = new Uint8Array(4 + header.length + body.length);
  new DataView(frame.buffer).setUint32(0, header.length, true);
  frame.set(header, 4);
  frame.set(body, 4 + header.length);

  const fd = os.open(HTTP_DEVICE, os.O_RDWR);
  if (fd < 0) {
    if (-fd === ENOENT) throw notAllowed();
    throw new TypeError(`fetch failed: cannot open the network device (errno ${-fd})`);
  }
  let data;
  try {
    writeAll(fd, frame);
    data = readAll(fd);
  } finally {
    os.close(fd);
  }
  if (data.length < 4) throw new TypeError('fetch failed: malformed response from the network broker');
  const n = new DataView(data.buffer, data.byteOffset, data.byteLength).getUint32(0, true);
  const meta = JSON.parse(utf8Decode(data.subarray(4, 4 + n)));
  if (meta.error) {
    const { code, message } = meta.error;
    throw new TypeError(`fetch failed: ${message}`, { cause: { code, message } });
  }
  const payload = method === 'HEAD' ? new Uint8Array(0) : data.subarray(4 + n);
  return Response._fromBroker(payload, meta);
}

function fetch(input, init) {
  return new Promise((resolve, reject) => {
    try {
      resolve(doFetch(input, init));
    } catch (e) {
      reject(e);
    }
  });
}

return { fetch, Headers, Response };
})
