// sandboxd JavaScript bootstrap (cycle 2, C2-U3).
//
// Launched as `qjs --std -m -I /usr/local/lib/sandboxd/boot.js /code/main.mjs <args>`. QuickJS
// evaluates `-I` includes as classic scripts before the program, so the program is not wrapped:
// `scriptArgs` and stack traces are unchanged.
//
// Kept tiny on purpose (NFR-N3: runs that don't use the network must not pay for it). It removes
// the `std`/`os`/`bjson` globals that `--std` created (the program sees the same globals as in
// cycle 1) and defines `fetch`, `Headers` and `Response` as lazy, non-enumerable globals: the
// implementation (fetch.js) is read and evaluated only when one of them is first used.
(() => {
  'use strict';
  const g = globalThis;
  const std = g.std;
  const os = g.os;
  delete g.std;
  delete g.os;
  delete g.bjson;
  let impl = null;
  const load = () => {
    if (impl === null) {
      const src = std.loadFile('/usr/local/lib/sandboxd/fetch.js');
      if (src === null) throw new Error('sandboxd: fetch.js is missing');
      impl = (0, eval)(src)(os);
    }
    return impl;
  };
  for (const name of ['fetch', 'Headers', 'Response']) {
    const define = (value) =>
      Object.defineProperty(g, name, { value, writable: true, configurable: true, enumerable: false });
    Object.defineProperty(g, name, {
      configurable: true,
      enumerable: false,
      get() {
        const value = load()[name];
        define(value);
        return value;
      },
      set(value) {
        define(value);
      },
    });
  }
})();
