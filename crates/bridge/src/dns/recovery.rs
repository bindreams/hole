//! DNS crash recovery — the evidence-gated upgrade sweep (bindreams/hole#846).
//!
//! The bridge itself no longer writes `bridge-dns.json` — DNS is confined
//! to `hole-tun` (see `tun_engine::dns_confine`), which persists nothing.
//! What remains here is the one place a write to another adapter is still
//! correct: undoing an older build's own upstream-adapter DNS rewrite
//! after that build crashed. Runs at bridge startup *after* the IPC socket
//! bind and *before* `routing::recover_routes` — matches the existing
//! convention in [`crate::plugin_recovery`] /
//! [`tun_engine::routing::recover_routes`].
//!
//! ## The gate, per adapter AND per family
//!
//! For each recorded adapter, and each of its two families independently,
//! [`system::restore_family_if_ours`] compares the family's LIVE setting
//! against the matching subset of the file's `advertised` field:
//!
//! - Live equals the subset → the setting is still what Hole put there →
//!   restore that family to its recorded prior (or note it's already
//!   correct).
//! - Live differs → someone else owns that family now → skip it, write
//!   nothing. This family alone blocks the file from being deleted (below).
//! - `advertised`'s subset for that family is empty → no sound evidence
//!   either way → skip, write nothing. Whether this blocks deletion depends
//!   on WHY the subset is empty: if `advertised` overall is non-empty (the
//!   shipped default is v4-only, so this is the common case for v6), Hole
//!   genuinely never claimed this family and there is nothing it could owe
//!   — it does NOT block. If `advertised` is empty in its ENTIRETY (a file
//!   of unknown provenance), every family reads this way and the whole file
//!   is treated as unconfirmed.
//!
//! Per family, not per adapter: a per-adapter verdict would let the v6
//! family — which Hole never wrote — veto the v4 restore that is genuinely
//! owed, or vice versa.
//!
//! ## Evaluated at most once
//!
//! After evaluating every recorded adapter, the file is DELETED if every
//! family settled (see [`settled`]'s doc for the exact rule); otherwise it
//! is renamed to [`dns_state::SUPERSEDED_FILE_NAME`] with a `warn!` naming
//! `scripts/network-reset.py`. Either way the un-suffixed name
//! ([`dns_state::STATE_FILE_NAME`]) is gone after this call, so
//! [`dns_state::load`] can never see it again on a later start — the
//! value-equality gate above is evidence, not ownership, and without this
//! bound it would stay armed for the life of the machine, re-evaluating the
//! same stale evidence on every later start. This mirrors the precedent at
//! `tun_engine::routing::failclosed`'s cover state-file handling: an
//! unconfirmed restore must not clear the escape hatch.
//! `scripts/network-reset.py` reads both names, so the escape survives the
//! rename rather than being hidden by it.

use std::net::IpAddr;
use std::path::Path;

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
/// `Restored` / `AlreadyCorrect` always settle. `NoEvidence` settles ONLY
/// when `advertised_totally_empty` is `false` — i.e. only when THIS
/// family's subset was empty while `advertised` overall was not (Hole
/// genuinely never touched this family; there is nothing for it to owe).
/// When `advertised` is empty in its ENTIRETY the file is of unknown
/// provenance: every family reads as `NoEvidence` and NONE of them may
/// settle, so the file is preserved rather than deleted. `SkippedNotOurs`
/// / `Failed` never settle — someone else may own that family now, or the
/// read/write itself failed.
fn settled(outcome: system::FamilyOutcome, advertised_totally_empty: bool) -> bool {
    match outcome {
        system::FamilyOutcome::Restored | system::FamilyOutcome::AlreadyCorrect => true,
        system::FamilyOutcome::NoEvidence => !advertised_totally_empty,
        system::FamilyOutcome::SkippedNotOurs | system::FamilyOutcome::Failed => false,
    }
}

/// Clean up system DNS settings left behind by an older build's crashed run.
/// Best-effort — errors logged at `warn`, returns `()`. Production entry
/// point; uses the real platform backend. Tests drive
/// [`recover_dns_config_with`] directly with a mock so the write side
/// (which requires elevation against a real adapter) is exercisable in CI.
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
        // `clear`'s own failure must not leave the un-suffixed name behind —
        // this call's whole promise (module doc) is that it's gone either
        // way. Falling back to `supersede` keeps that promise AND keeps the
        // file itself alive as `scripts/network-reset.py`'s escape hatch,
        // even though the restore actually succeeded.
        if let Err(e) = dns_state::clear(state_dir) {
            tracing::warn!(
                error = %e,
                "dns_recovery: failed to clear bridge-dns.json after full restore; superseding it instead"
            );
            if let Err(e) = dns_state::supersede(state_dir) {
                tracing::warn!(error = %e, "dns_recovery: failed to rename bridge-dns.json to the superseded name");
            }
        }
    } else {
        tracing::warn!(
            "dns_recovery: could not confirm every recorded adapter/family was still Hole's own prior DNS; \
             preserving the file as bridge-dns.superseded.json. Run scripts/network-reset.py if DNS looks wrong."
        );
        if let Err(e) = dns_state::supersede(state_dir) {
            tracing::warn!(error = %e, "dns_recovery: failed to rename bridge-dns.json to the superseded name");
        }
    }
}

#[cfg(test)]
#[path = "recovery_tests.rs"]
mod recovery_tests;
