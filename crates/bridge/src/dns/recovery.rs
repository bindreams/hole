//! DNS crash recovery: the evidence-gated upgrade sweep.
//!
//! The bridge does not write `bridge-dns.json`; DNS is confined to
//! `hole-tun` (see `tun_engine::dns_confine`), which persists nothing. What
//! remains is the one place a write to another adapter is still correct:
//! undoing an older build's upstream-adapter DNS rewrite after that build
//! crashed. It runs at bridge startup after the IPC socket bind and before
//! `routing::recover_routes`, like [`crate::plugin_recovery`].
//!
//! ## The gate, per adapter and per family
//!
//! For each recorded adapter, and each of its two families independently,
//! [`system::restore_family_if_ours`] compares the family's live setting
//! against the matching subset of the file's `advertised` field:
//!
//! - Live equals the subset: the setting is still what Hole put there, so
//!   restore that family to its recorded prior (or note it is already
//!   correct).
//! - Live differs: someone else owns that family now, so write nothing. This
//!   family alone blocks the file from being deleted (below).
//! - The subset is empty: no sound evidence either way, so write nothing.
//!   Whether this blocks deletion depends on why it is empty. If `advertised`
//!   overall is non-empty, Hole never claimed this family and owes nothing, so
//!   it does not block. If `advertised` is empty in its entirety (a file of
//!   unknown provenance), every family reads this way and the whole file is
//!   unconfirmed.
//!
//! The gate is per family, not per adapter: a per-adapter verdict would let a
//! family Hole never wrote veto the restore genuinely owed on the other.
//!
//! ## Evaluated at most once
//!
//! After evaluating every recorded adapter, the file is deleted if every
//! family settled (see [`settled`]); otherwise it is renamed to
//! [`dns_state::SUPERSEDED_FILE_NAME`] with a `warn!` naming
//! `scripts/network-reset.py`. Either way the un-suffixed name
//! ([`dns_state::STATE_FILE_NAME`]) is gone after this call, so
//! [`dns_state::load`] never sees it on a later start. The value-equality gate
//! is evidence, not ownership: without this bound it would stay armed for the
//! life of the machine, re-judging the same stale evidence on every start.
//! An unconfirmed restore must not clear the escape hatch, and
//! `scripts/network-reset.py` reads both names.

use std::net::IpAddr;
use std::path::Path;

use util::versioned_file::UpdateOutcome;

use crate::dns::system;
use crate::dns_state::{self, AdapterId};

/// Split `advertised` into its v4 and v6 subsets — what
/// [`system::restore_family_if_ours`] compares each family's live setting
/// against. The union is never compared directly; see the module doc.
fn split_advertised(advertised: &[IpAddr]) -> (Vec<IpAddr>, Vec<IpAddr>) {
    advertised.iter().copied().partition(|ip| ip.is_ipv4())
}

/// Whether an outcome counts as "this family is settled" for the
/// once-only bound.
///
/// `Restored` / `AlreadyCorrect` always settle. `NoEvidence` settles only
/// when `advertised_totally_empty` is `false`, i.e. this family's subset was
/// empty while `advertised` overall was not: Hole never touched the family
/// and owes nothing. When `advertised` is empty in its entirety the file is of
/// unknown provenance, every family reads as `NoEvidence`, and none may
/// settle, so the file is preserved rather than deleted. `SkippedNotOurs` and
/// `Failed` never settle: someone else may own that family now, or the
/// read/write itself failed.
fn settled(outcome: system::FamilyOutcome, advertised_totally_empty: bool) -> bool {
    match outcome {
        system::FamilyOutcome::Restored | system::FamilyOutcome::AlreadyCorrect => true,
        system::FamilyOutcome::NoEvidence => !advertised_totally_empty,
        system::FamilyOutcome::SkippedNotOurs | system::FamilyOutcome::Failed => false,
    }
}

/// Clean up system DNS settings left behind by an older build's crashed run.
/// Best-effort: nothing is returned. A file that cannot be cleared or
/// superseded is logged at `warn`; the `io::Error` behind a family's
/// `Failed` outcome is discarded, so only the outcome reaches the per-adapter
/// `info` line (bindreams/hole#1321). Uses the real platform backend; tests drive [`recover_dns_config_with`] with a mock,
/// since the write side needs elevation against a real adapter.
pub fn recover_dns_config(state_dir: &Path) {
    #[cfg(target_os = "windows")]
    recover_dns_config_with(state_dir, &system::windows::Win32Real);
    #[cfg(target_os = "macos")]
    recover_dns_config_with(state_dir, &system::macos::Networksetup);
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        let _ = state_dir;
    }
}

#[cfg(target_os = "windows")]
pub(crate) fn recover_dns_config_with(state_dir: &Path, backend: &dyn system::windows::WinDnsBackend) {
    let Some(state) = dns_state::load(state_dir) else {
        return;
    };
    let (v4_advertised, v6_advertised) = split_advertised(&state.advertised);
    let advertised_totally_empty = state.advertised.is_empty();

    let mut fully_settled = true;
    for adapter in &state.adapters {
        let AdapterId::WindowsAlias { value: alias } = &adapter.id else {
            // A v1 file recorded under a different platform's identifier
            // shape — no evidence this backend can evaluate.
            fully_settled = false;
            continue;
        };
        let v4 = system::restore_family_if_ours(backend, alias, false, &adapter.v4, &v4_advertised);
        let v6 = system::restore_family_if_ours(backend, alias, true, &adapter.v6, &v6_advertised);
        tracing::info!(id = ?adapter.id, ?v4, ?v6, "dns_recovery: upgrade sweep evaluated adapter");
        fully_settled &= settled(v4, advertised_totally_empty) && settled(v6, advertised_totally_empty);
    }

    finish(state_dir, fully_settled);
}

#[cfg(target_os = "macos")]
pub(crate) fn recover_dns_config_with(state_dir: &Path, backend: &dyn system::macos::MacDnsBackend) {
    let Some(state) = dns_state::load(state_dir) else {
        return;
    };
    let (v4_advertised, v6_advertised) = split_advertised(&state.advertised);
    let advertised_totally_empty = state.advertised.is_empty();

    let mut fully_settled = true;
    for adapter in &state.adapters {
        let AdapterId::MacosServiceName { value: service } = &adapter.id else {
            fully_settled = false;
            continue;
        };
        let v4 = system::restore_family_if_ours(backend, service, false, &adapter.v4, &v4_advertised);
        let v6 = system::restore_family_if_ours(backend, service, true, &adapter.v6, &v6_advertised);
        tracing::info!(id = ?adapter.id, ?v4, ?v6, "dns_recovery: upgrade sweep evaluated adapter");
        fully_settled &= settled(v4, advertised_totally_empty) && settled(v6, advertised_totally_empty);
    }

    finish(state_dir, fully_settled);
}

/// Delete the file on full success; otherwise rename it to the superseded
/// name with a `warn!` naming the escape script. Either branch is one
/// evaluation, ever — see the module doc.
fn finish(state_dir: &Path, fully_settled: bool) {
    if fully_settled {
        // A failed `clear` must not leave the un-suffixed name behind (module
        // doc). Falling back to `supersede` keeps that promise and keeps the
        // file as `scripts/network-reset.py`'s escape hatch, though the
        // restore succeeded.
        let cleared = match dns_state::clear(state_dir) {
            Ok(UpdateOutcome::Removed | UpdateOutcome::Absent) => true,
            Ok(outcome) => {
                tracing::warn!(
                    ?outcome,
                    "dns_recovery: bridge-dns.json was not cleared after full restore"
                );
                false
            }
            Err(e) => {
                tracing::warn!(
                    error = &e as &dyn std::error::Error,
                    "dns_recovery: failed to clear bridge-dns.json after full restore"
                );
                false
            }
        };
        if !cleared {
            tracing::warn!("dns_recovery: superseding bridge-dns.json instead");
            if let Err(e) = dns_state::supersede(state_dir) {
                tracing::warn!(
                    error = &e as &dyn std::error::Error,
                    "dns_recovery: failed to rename bridge-dns.json to the superseded name"
                );
            }
        }
    } else {
        tracing::warn!(
            "dns_recovery: could not confirm every recorded adapter/family was still Hole's own prior DNS; \
             preserving the file as bridge-dns.superseded.json. Run scripts/network-reset.py if DNS looks wrong."
        );
        if let Err(e) = dns_state::supersede(state_dir) {
            tracing::warn!(
                error = &e as &dyn std::error::Error,
                "dns_recovery: failed to rename bridge-dns.json to the superseded name"
            );
        }
    }
}

#[cfg(test)]
#[path = "recovery_tests.rs"]
mod recovery_tests;
