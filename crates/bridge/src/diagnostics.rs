//! Diagnostics — structured logging helpers that attach extra context
//! when an operation fails in a way the raw error doesn't explain.
//!
//! Currently a single module, [`file_locks`], which answers "which
//! processes have a handle to this file" on spawn-time `ACCESS_DENIED`
//! / `ETXTBSY` errors.

pub mod file_locks;
pub mod spawn;
