// Compile-only check of index.d.ts (`tsc --noEmit -p clients/js/test`): typical usage must type-check.
import { Sandboxd, SandboxdError, type RunResult, type StreamEvent, type SessionInfo } from "../index.js";

async function main(): Promise<void> {
  const sbx = new Sandboxd({ url: "http://127.0.0.1:8080", token: "t", timeoutMs: 5000, retries: 1 });
  const r: RunResult = await sbx.run("print(1)", {
    language: "python",
    files: { "a.txt": "x", "b.bin": new Uint8Array([1]) },
    args: ["a"],
    stdin: "in",
    limits: { wall_clock: "2s", memory: "64MiB" },
  });
  const ok: boolean = r.ok;
  const code: number | null = r.exitCode;
  const bytes: Uint8Array = r.artifact("x").content;
  void [ok, code, bytes, r.timings.totalMs, r.error?.code];

  for await (const ev of sbx.stream("print(1)")) {
    const e: StreamEvent = ev;
    if (e.type === "stdout") console.log(e.text.length, e.data.byteLength);
    else if (e.type === "limit") console.log(e.limit);
    else if (e.type === "result") console.log(e.result.outcome);
  }

  const s = await sbx.createSession({ language: "javascript", policy: "notebook" });
  await s.run("globalThis.x = 1", { limits: { wall_clock: "1s" } });
  const info: SessionInfo = await s.info();
  void info.idleTimeoutS;
  await s.close();
  {
    await using t = await sbx.createSession();
    void t.id;
  }

  try {
    await sbx.health();
  } catch (e) {
    if (e instanceof SandboxdError) console.log(e.code, e.status, e.detail);
  }
  const names: string[] = (await sbx.policies()).map((p) => p.name);
  void names;
}

void main;
