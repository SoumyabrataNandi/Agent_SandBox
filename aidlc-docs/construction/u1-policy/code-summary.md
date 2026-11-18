# U1 Policy — Code Summary & Test Results (2026-11-18)

Design answers: Q1 serde-saphyr, Q2 binary units, Q3 refuse grants until supported (all A).

| File | Content |
|---|---|
| `src/units.rs` | Exact parsers: `parse_bytes` (all binary), `parse_duration` (unit required), `parse_fuel` (×1000); u128 arithmetic, overflow-checked, decimals exact or rejected |
| `src/raw.rs` | One serde shape for TOML + YAML, `deny_unknown_fields` everywhere, `Quantity` keeps unit strings for field-precise errors |
| `src/model.rs` | `Policy`/`PolicySpec`, validation of R1–R12 (collects every error), `tighten` (R8), `ensure_supported` (Q3), `explain` + `warnings`, hardened YAML options |
| `src/dir.rs` | `PolicyDir::load`: non-recursive, hidden files skipped, symlink containment, name = stem, duplicates, all-or-nothing, built-in `default` (overridable), policy dir added to forbidden mount roots |
| `src/error.rs` | `PolicyError` / `PolicyErrors` (origin + field path; env values never echoed) |
| `tests/policy.rs`, `tests/golden/*` | 20 integration tests incl. 3 proptests |

**Tests:** 24 (4 unit + 20 integration). This includes TOML↔YAML parity on golden files (acceptance criterion 9), and YAML anchors, aliases, duplicate keys, multiple documents and merge keys each refused with line/column. Proptests check that `tighten` never widens and that the parsers never panic.

**Note:** YAML hardening sets anchors and aliases to 0. Operators can't use YAML anchors in policies, by design.
