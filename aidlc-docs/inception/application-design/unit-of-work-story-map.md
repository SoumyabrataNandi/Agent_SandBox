# Requirements → Unit Map (User Stories skipped, Q20=A)

| Requirement / Acceptance criterion | U0 | U1 | U2 | U3 | U4 | U5 | U6 |
|---|---|---|---|---|---|---|---|
| FR-1 Execution engine |  |  |  |  | ● |  | ✓ |
| FR-2 Resource limits |  | ○ |  |  | ● | ○ (2.5) | ✓ |
| FR-3 Virtual filesystem |  |  |  | ● | ○ |  | ✓ |
| FR-4 Policy engine |  | ● |  |  |  | ○ |  |
| FR-5 Interfaces (CLI/HTTP/MCP/auth) |  |  |  |  |  | ● | ✓ |
| FR-6 Audit & telemetry |  |  | ● | ○ | ○ | ○ |  |
| FR-7 Network broker (design only) |  | ○ schema |  | ○ vfd seam | ○ trait |  |  |
| FR-8 Pool/session seams |  | ○ schema |  |  | ● |  |  |
| NFR-1 3-OS first-class | ● |  |  |  |  |  | ✓ |
| NFR-2 Single binary, embedded assets | ● |  |  | ○ stdlib | ○ cache |  |  |
| NFR-3 Latency targets |  |  |  |  | ● |  | ✓ |
| NFR-4 Security baseline + escape suite | ● tooling |  | ○ redaction | ● | ● | ● | ● |
| NFR-7 License | ● |  |  |  |  |  |  |
| AC1 hello.py / hello.js |  |  |  |  | ● |  | ✓ |
| AC2 timeout / fuel |  |  |  |  | ● |  | ✓ |
| AC3 memory cap |  |  |  |  | ● |  | ✓ |
| AC4 no host data, denials audited |  |  |  | ● |  |  | ✓ |
| AC5 ro input, /out artifact |  |  |  | ● |  |  | ✓ |
| AC6 numpy → UNSUPPORTED |  |  |  |  | ● |  |  |
| AC7 MCP from Claude |  |  |  |  |  | ● |  |
| AC8 auth + bind safety |  |  |  |  |  | ● | ✓ |
| AC9 TOML/YAML parity |  | ● |  |  |  |  |  |
| AC10 escape suite on 3 OSes |  |  |  |  |  |  | ● |

● primary owner · ○ contributes · ✓ verified by escape suite / CI
