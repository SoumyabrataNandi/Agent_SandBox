//! Guest filesystem for sandboxd (component C3, unit U3).
//!
//! Per-run temp roots, mount table, the WASI p1 interposer (ADR-001), the virtual-fd table
//! (ADR-002) and artifact collection. Implemented in U3, starting with the ADR-001 spike.
//!
//! This crate is one of two allowed to contain `unsafe` (guest memory access); every use
//! needs a `// SAFETY:` comment and review.
