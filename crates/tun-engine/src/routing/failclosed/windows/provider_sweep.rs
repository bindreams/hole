//! The version-independent half of the full sweeps: boot-time filters under [`PROVIDER_GUID`] that no key list in
//! this build names.
//!
//! A twin installed by another build — a newer one, whose GUID this build never learned — has no persistent
//! counterpart BFE would re-add and no key an older binary can delete by, so `release_all` and
//! `disengage_lockdown` find it by enumeration instead. The by-key pass runs first and owns every key a list
//! names; this pass owns the rest.
//!
//! The scope is exactly "boot-time AND ours". A persistent filter under the same provider is left alone on purpose:
//! a live one may be another bridge's cover, which no sweep of this build may delete. Another provider's filter is
//! never in scope either.
//!
//! The enumeration names every layer and no provider. A template needs a layer, so the layers are listed from the
//! engine rather than hardcoded, and the provider is selected in code by [`unrecognised_keys`], so the selection is
//! testable without a firewall.

use std::fmt;

use super::super::readback;
use super::*;

/// What an operator is told about a delete this pass issued: the key class, then the filter's GUID. With the binary
/// gone the GUID is what the filter can be matched by in `netsh wfp show boottimepolicy`.
pub(super) const UNRECOGNISED_LABEL: &str = "unrecognised boot-time filter";

/// What an operator is told when the pass could not enumerate. Distinct from [`UNRECOGNISED_LABEL`] because the two
/// are different findings: one is a filter the OS refused to delete, the other is a sweep that could not look.
pub(super) const UNENUMERATED_LABEL: &str = "boot-time filters under Hole's provider";

/// A boot-time view that could not be read, and why.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ViewFailure {
    /// One layer's view, and the code the OS answered.
    Layer { layer: GUID, code: u32 },
    /// The list of layers could not be read.
    LayerList { code: u32 },
    /// The list of layers was read and is empty: the OS answered success and named nothing to enumerate, so nothing was
    /// looked at.
    NoLayers,
}

impl fmt::Display for ViewFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ViewFailure::Layer { layer, code } => write!(f, "layer {layer:?}: 0x{code:08x}"),
            ViewFailure::LayerList { code } => write!(f, "the list of layers: 0x{code:08x}"),
            ViewFailure::NoLayers => write!(f, "the list of layers: empty"),
        }
    }
}

/// One boot-time view of one layer, as read.
pub(super) type LayerRead = Result<Vec<FilterRecord>, ViewFailure>;

/// The sweep entry for a key found by enumeration. Its label names the GUID; its lifetime is the one
/// [`unrecognised_keys`] selects on, so a delete's outcome is read under the lifetime of the object it removed.
pub(super) fn unrecognised_key(guid: GUID) -> SweptKey {
    SweptKey {
        guid,
        label: format!("{UNRECOGNISED_LABEL} {}", netsh_guid(guid)).into(),
        lifetime: FilterLifetime::BOOT_TIME,
        role: KeyRole::Unlisted,
    }
}

/// A GUID as `netsh wfp` prints a filter key: braced, lowercase.
fn netsh_guid(g: GUID) -> String {
    format!("{{{g:?}}}").to_lowercase()
}

/// The keys of `records` this pass deletes: boot-time, under [`PROVIDER_GUID`], and named by no fixed list. Each
/// key once, in first-seen order — the views overlap.
///
/// A fixed list's keys are excluded because the by-key pass already issued their delete and recorded their
/// observation; a second delete would observe them twice.
pub(super) fn unrecognised_keys(records: &[FilterRecord]) -> Vec<GUID> {
    let known: Vec<GUID> = swept_lockdown_keys()
        .into_iter()
        .chain(swept_transient_keys())
        .map(|k| k.guid)
        .collect();
    let mut keys: Vec<GUID> = Vec::new();
    for r in records {
        let ours = r.provider == Some(PROVIDER_GUID);
        if ours && r.is_boottime() && !known.contains(&r.key) && !keys.contains(&r.key) {
            keys.push(r.key);
        }
    }
    keys
}

/// What the provider sweep did: the unrecognised keys it deleted, with the codes their deletes answered, and the
/// first view it could not read.
///
/// Held apart from the by-key lists' results only because they come from a different read; the verdicts fold both
/// through `first_sweep_failure`, which a refused stranger's delete does not fail: it stays in the clearance.
///
/// An unreadable view says nothing about whether a stranger is installed, so it is an unproven boot-time observation
/// ([`Self::observations`]) rather than either a proof or a failure of the sweep, and is always reported
/// ([`KeyRole::Enumeration`]).
#[derive(Debug)]
pub(super) struct ProviderSweep {
    pub(super) swept: Vec<(SweptKey, u32)>,
    pub(super) unread: Option<ViewFailure>,
}

impl ProviderSweep {
    /// What this sweep adds to the clearance: each stranger's delete, and one unproven observation if a view could not
    /// be read. A complete read adds nothing: an empty boot-time view after BFE started is not proof that no record
    /// survives behind it, so it must not become one.
    pub(super) fn observations(&self) -> Vec<KeyObservation> {
        let mut observed = observations(&self.swept);
        observed.extend(self.unread.map(|_| KeyObservation {
            key: UNENUMERATED_LABEL.into(),
            lifetime: KeyLifetime::BootTime,
            outcome: KeyOutcome::Failed,
            role: KeyRole::Enumeration,
            code: None,
        }));
        observed
    }
}

/// Delete every unrecognised key in `views`, and report the first view that could not be read; no view at all is
/// [`ViewFailure::NoLayers`].
///
/// Every delete is issued before any code is read, like the by-key pass. A view that could not be read does not
/// hide what the others returned.
pub(super) fn sweep_unrecognised(views: &[LayerRead], mut delete: impl FnMut(&GUID) -> u32) -> ProviderSweep {
    let (records, unread) = readback::merge(views);
    let swept = unrecognised_keys(&records)
        .into_iter()
        .map(|guid| {
            let code = delete(&guid);
            (unrecognised_key(guid), code)
        })
        .collect();
    // `merge` reads no view as every view read; here it is no look taken.
    let unread = if views.is_empty() {
        Some(ViewFailure::NoLayers)
    } else {
        unread.copied()
    };
    ProviderSweep { swept, unread }
}

/// The boot-time view of every layer in `layers`, both enumeration types each, read through `read`. A list of layers
/// that could not be read, or that is empty, is one failed view that names no layer.
///
/// Both types are read for the reason `verify_boottime_twins` reads both: WFP's reference does not say what
/// `enumType` means for a template with no conditions, and a filter a build adds later may carry conditions.
pub(super) fn read_layer_views(
    layers: Result<Vec<GUID>, u32>,
    mut read: impl FnMut(GUID, FWP_FILTER_ENUM_TYPE) -> Result<Vec<FilterRecord>, u32>,
) -> Vec<LayerRead> {
    let layers = match layers {
        Ok(layers) if layers.is_empty() => return vec![Err(ViewFailure::NoLayers)],
        Ok(layers) => layers,
        Err(code) => return vec![Err(ViewFailure::LayerList { code })],
    };
    let mut views = Vec::with_capacity(layers.len() * 2);
    for layer in layers {
        for enum_type in [FWP_FILTER_ENUM_FULLY_CONTAINED, FWP_FILTER_ENUM_OVERLAPPING] {
            views.push(read(layer, enum_type).map_err(|code| ViewFailure::Layer { layer, code }));
        }
    }
    views
}

/// The boot-time view of every layer the engine has, on an already-open `engine`.
///
/// # Safety
///
/// `engine` must be a live FWPM engine handle with no open transaction.
pub(super) unsafe fn read_provider_views(engine: HANDLE) -> Vec<LayerRead> {
    read_layer_views(enum_layers(engine), |layer, enum_type| {
        enum_boottime_on(engine, layer, enum_type)
    })
}

/// [`sweep_unrecognised`] against a live engine, over [`read_provider_views`].
///
/// # Safety
///
/// `engine` must be a live FWPM engine handle with no open transaction.
#[allow(clippy::disallowed_methods)] // sanctioned FWPM call site
pub(super) unsafe fn sweep_provider(engine: HANDLE) -> ProviderSweep {
    let views = read_provider_views(engine);
    for failure in views.iter().filter_map(|v| v.as_ref().err()) {
        tracing::warn!(
            view = %failure,
            "could not enumerate boot-time filters under Hole's provider; a stranger left by another version \
             would not have been swept"
        );
    }
    let sweep = sweep_unrecognised(&views, |g| FwpmFilterDeleteByKey0(engine, g));
    for (key, code) in &sweep.swept {
        tracing::warn!(
            key = %key.label,
            code = format!("0x{code:08x}"),
            outcome = ?classify_delete_code(*code),
            "found a boot-time filter under Hole's provider that this build does not know, left by another version"
        );
    }
    sweep
}

#[cfg(test)]
#[path = "provider_sweep_tests.rs"]
mod provider_sweep_tests;
