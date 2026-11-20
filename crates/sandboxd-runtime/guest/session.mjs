// sandboxd session loop for JavaScript (cycle 3, C3-U4).
//
// Runs as the main module of one live QuickJS instance for the whole session. Each call arrives
// through /dev/sandbox/session: a read blocks (host-side) until the next call and returns
// {"cell": N, "path": "/code/cell_N.mjs", "args": [...]}. The cell runs as a *global script* with
// top-level await (design Q8 of the application design), so var/let/const/function/class
// declarations persist across cells; `import` statements are not allowed in cells (use
// `await import(...)`). The loop writes {"status": "ok"|"error", "exit_code": n} back; an empty
// read ends the session.

import * as std from 'qjs:std';
import * as os from 'qjs:os';

const DEVICE = '/dev/sandbox/session';

// UTF-8 via the Annex B escape/unescape pair (QuickJS has no TextEncoder/TextDecoder).
function decode(bytes) {
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return decodeURIComponent(escape(s));
}

function encode(text) {
  const s = unescape(encodeURIComponent(text));
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}

// As qjs reports an uncaught error: the error, then its stack.
function report(e) {
  let text = String(e) + '\n';
  if (e && typeof e.stack === 'string' && e.stack.length > 0) text += e.stack;
  std.err.puts(text.endsWith('\n') ? text : text + '\n');
}

function setArgs(args) {
  try {
    Object.defineProperty(globalThis, 'scriptArgs', {
      value: args,
      writable: true,
      configurable: true,
      enumerable: false,
    });
  } catch (_) {
    globalThis.scriptArgs = args;
  }
}

const fd = os.open(DEVICE, os.O_RDWR);
const buf = new ArrayBuffer(1 << 16);
for (;;) {
  const n = os.read(fd, buf, 0, buf.byteLength);
  if (n <= 0) break;
  const frame = JSON.parse(decode(new Uint8Array(buf, 0, n)));
  setArgs([frame.path, ...(frame.args || [])]);
  let status = 'ok';
  let code = 0;
  try {
    const source = std.loadFile(frame.path);
    if (source === null) throw new Error(`cannot load ${frame.path}`);
    await std.evalScript(source, { async: true });
  } catch (e) {
    status = 'error';
    code = 1;
    report(e);
  }
  std.out.flush();
  std.err.flush();
  const reply = encode(JSON.stringify({ status, exit_code: code }));
  os.write(fd, reply.buffer, 0, reply.length);
}
os.close(fd);
