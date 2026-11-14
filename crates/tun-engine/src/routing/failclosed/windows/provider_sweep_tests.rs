use super::super::windows_tests::{clean_provider_sweep, sweep_answering, swept};
use super::*;
use crate::routing::failclosed::boottime_witness::WitnessUpdate;
use crate::routing::failclosed::clearance_tests::pairs;
use crate::GLOBAL_NET_STATE;

const OTHER_PROVIDER: GUID = GUID::from_u128(0x5eeb_0000_0000_4000_8000_0000_0000_0001);

/// A key no list in this build names: what a newer build's twin looks like to this one.
fn stranger(n: u128) -> GUID {
    GUID::from_u128(0x7a11_0000_0000_4000_8000_0000_0000_0000 | n)
}

/// A layer no cover installs at, as a layer a later build adds would look.
fn other_layer(n: u128) -> GUID {
    GUID::from_u128(0x1a7e_0000_0000_4000_8000_0000_0000_0000 | n)
}

fn record(key: GUID, boot_time: bool, provider: Option<GUID>, layer: GUID) -> FilterRecord {
    FilterRecord {
        key,
        flags: if boot_time {
            FWPM_FILTER_FLAG_BOOTTIME.0
        } else {
            FWPM_FILTER_FLAG_PERSISTENT.0
        },
        provider,
        sublayer: SUBLAYER_GUID,
        layer,
        filter_id: 1,
    }
}

fn ours_boot_time(key: GUID) -> FilterRecord {
    record(key, true, Some(PROVIDER_GUID), FWPM_LAYER_ALE_AUTH_CONNECT_V4)
}

/// A layer whose view could not be read, with `code`.
fn unreadable(layer: GUID, code: u32) -> LayerRead {
    Err(ViewFailure::Layer { layer, code })
}

// Selection ===========================================================================================================

#[skuld::test]
fn a_boot_time_filter_no_list_names_is_targeted_at_every_layer_the_cover_can_install_at() {
    let layers = [
        FWPM_LAYER_ALE_AUTH_CONNECT_V4,
        FWPM_LAYER_ALE_AUTH_CONNECT_V6,
        FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
        FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
    ];
    let records: Vec<FilterRecord> = layers
        .iter()
        .enumerate()
        .map(|(i, &layer)| record(stranger(i as u128), true, Some(PROVIDER_GUID), layer))
        .collect();
    assert_eq!(unrecognised_keys(&records), (0..4).map(stranger).collect::<Vec<_>>());
}

#[skuld::test]
fn a_boot_time_filter_at_a_layer_no_build_installs_at_is_still_targeted() {
    // The layers are not a list this build carries: a later build may install at one it never learned.
    let records = [record(stranger(1), true, Some(PROVIDER_GUID), other_layer(1))];
    assert_eq!(unrecognised_keys(&records), vec![stranger(1)]);
}

#[skuld::test]
fn no_sweep_targets_another_providers_filter_or_one_with_no_provider() {
    // The safety property, asserted on the selector: the per-layer enumeration names no provider, so this is the
    // only place the provider is chosen.
    let records = [
        record(stranger(2), true, Some(OTHER_PROVIDER), FWPM_LAYER_ALE_AUTH_CONNECT_V4),
        record(stranger(3), true, None, FWPM_LAYER_ALE_AUTH_CONNECT_V4),
    ];
    assert_eq!(unrecognised_keys(&records), Vec::<GUID>::new());
}

#[skuld::test]
fn a_persistent_filter_is_never_targeted() {
    // A live persistent filter under the provider may be another bridge's cover, so no sweep takes one whatever its
    // key, even when the record is handed to the selector (a persistent filter is outside the boot-time view).
    let records = [
        record(stranger(1), false, Some(PROVIDER_GUID), FWPM_LAYER_ALE_AUTH_CONNECT_V4),
        ours_boot_time(stranger(2)),
    ];
    assert_eq!(unrecognised_keys(&records), vec![stranger(2)]);
}

#[skuld::test]
fn a_filter_with_neither_a_persistent_nor_a_boot_time_flag_is_nobodys_leftover() {
    // A volatile filter dies with BFE; there is nothing for a sweep to strand.
    let volatile = FilterRecord {
        flags: 0,
        ..record(stranger(1), false, Some(PROVIDER_GUID), FWPM_LAYER_ALE_AUTH_CONNECT_V4)
    };
    assert_eq!(unrecognised_keys(&[volatile]), Vec::<GUID>::new());
}

#[skuld::test]
fn a_key_a_fixed_list_already_owns_is_not_an_unrecognised_one() {
    // The by-key pass deletes these and records their observation; deleting them again here would observe them twice.
    let records: Vec<FilterRecord> = swept_lockdown_keys()
        .into_iter()
        .chain(swept_transient_keys())
        .map(|k| ours_boot_time(k.guid))
        .collect();
    assert!(!records.is_empty());
    assert_eq!(unrecognised_keys(&records), Vec::<GUID>::new());
}

#[skuld::test]
fn a_filter_two_views_both_returned_is_targeted_once() {
    let records = [
        ours_boot_time(stranger(1)),
        ours_boot_time(stranger(2)),
        ours_boot_time(stranger(1)),
    ];
    assert_eq!(unrecognised_keys(&records), vec![stranger(1), stranger(2)]);
}

// The per-layer read ==================================================================================================

#[skuld::test]
fn every_layer_is_read_with_both_enumeration_types_in_layer_order() {
    let layers = vec![other_layer(1), other_layer(2)];
    let mut asked = Vec::new();
    let views = read_layer_views(Ok(layers.clone()), |layer, enum_type| {
        asked.push((layer, enum_type));
        Ok(vec![])
    });
    assert_eq!(
        asked,
        vec![
            (other_layer(1), FWP_FILTER_ENUM_FULLY_CONTAINED),
            (other_layer(1), FWP_FILTER_ENUM_OVERLAPPING),
            (other_layer(2), FWP_FILTER_ENUM_FULLY_CONTAINED),
            (other_layer(2), FWP_FILTER_ENUM_OVERLAPPING),
        ]
    );
    assert_eq!(views.len(), 4);
}

#[skuld::test]
fn a_layer_whose_view_fails_is_named_with_its_code_and_hides_no_other_layer() {
    let views = read_layer_views(Ok(vec![other_layer(1), other_layer(2)]), |layer, _| {
        if layer == other_layer(1) {
            Err(0x8032_0004)
        } else {
            Ok(vec![ours_boot_time(stranger(9))])
        }
    });
    let failures: Vec<&ViewFailure> = views.iter().filter_map(|v| v.as_ref().err()).collect();
    assert_eq!(failures.len(), 2, "both enumeration types of the failing layer");
    for f in failures {
        assert_eq!(
            *f,
            ViewFailure::Layer {
                layer: other_layer(1),
                code: 0x8032_0004
            }
        );
    }
    let mut deleted = Vec::new();
    let sweep = sweep_unrecognised(&views, |g| {
        deleted.push(*g);
        ERROR_SUCCESS.0
    });
    assert_eq!(
        deleted,
        vec![stranger(9)],
        "what the readable layer returned is still swept"
    );
    assert_eq!(
        sweep.unread,
        Some(ViewFailure::Layer {
            layer: other_layer(1),
            code: 0x8032_0004
        })
    );
}

#[skuld::test]
fn a_layer_list_that_could_not_be_read_is_one_unreadable_view_that_names_no_layer() {
    let views = read_layer_views(Err(0x8032_0002), |_, _| panic!("no layer was listed, so none is read"));
    assert_eq!(views.len(), 1);
    assert_eq!(views[0], Err(ViewFailure::LayerList { code: 0x8032_0002 }));
}

#[skuld::test]
fn an_unreadable_view_is_described_by_its_layer_and_its_code() {
    let layer = format!("{:?}", other_layer(1));
    let text = ViewFailure::Layer {
        layer: other_layer(1),
        code: 0x8032_0004,
    }
    .to_string();
    assert!(text.contains(&layer), "{text}");
    assert!(text.contains("0x80320004"), "{text}");
    let list = ViewFailure::LayerList { code: 0x8032_0002 }.to_string();
    assert!(list.contains("0x80320002"), "{list}");
    assert!(!list.contains(&layer), "{list}");
}

// Sweep over the enumeration views ====================================================================================

#[skuld::test]
fn the_sweep_deletes_what_the_views_returned_and_labels_it_boot_time() {
    let views = [
        Ok(vec![ours_boot_time(stranger(1))]),
        Ok(vec![ours_boot_time(stranger(2))]),
    ];
    let mut deleted = Vec::new();
    let sweep = sweep_unrecognised(&views, |g| {
        deleted.push(*g);
        ERROR_SUCCESS.0
    });
    assert_eq!(deleted, vec![stranger(1), stranger(2)]);
    assert!(sweep.unread.is_none());
    assert_eq!(sweep.swept.len(), 2);
    for (k, code) in &sweep.swept {
        assert!(k.label.starts_with(UNRECOGNISED_LABEL), "{}", k.label);
        assert_eq!(k.lifetime, FilterLifetime::BOOT_TIME);
        assert_eq!(k.role, KeyRole::Unlisted);
        assert_eq!(*code, ERROR_SUCCESS.0);
    }
}

#[skuld::test]
fn a_view_that_could_not_be_read_does_not_hide_what_the_other_one_returned() {
    let views = [
        unreadable(other_layer(1), 0x8032_0001),
        Ok(vec![ours_boot_time(stranger(7))]),
    ];
    let mut deleted = Vec::new();
    let sweep = sweep_unrecognised(&views, |g| {
        deleted.push(*g);
        ERROR_SUCCESS.0
    });
    assert_eq!(deleted, vec![stranger(7)]);
    assert_eq!(sweep.swept.len(), 1);
    assert_eq!(
        sweep.unread,
        Some(ViewFailure::Layer {
            layer: other_layer(1),
            code: 0x8032_0001
        })
    );
}

#[skuld::test]
fn two_unreadable_views_delete_nothing_and_say_so() {
    let views = [unreadable(other_layer(1), 5), unreadable(other_layer(2), 6)];
    let sweep = sweep_unrecognised(&views, |_| panic!("nothing was enumerated, so nothing is deleted"));
    assert!(sweep.swept.is_empty());
    assert_eq!(
        sweep.unread,
        Some(ViewFailure::Layer {
            layer: other_layer(1),
            code: 5
        }),
        "the first failure"
    );
}

#[skuld::test]
fn an_empty_list_of_layers_is_an_unreadable_enumeration_not_a_complete_read() {
    // The engine answered success with no layers: it has nothing to be enumerated, so a stranger could not have been
    // looked for. That is an OS answer to report, never a clean read and never a panic.
    let views = read_layer_views(Ok(vec![]), |_, _| panic!("no layer, no read"));
    let sweep = sweep_unrecognised(&views, |_| panic!("nothing was enumerated, so nothing is deleted"));
    assert!(sweep.swept.is_empty());
    assert_eq!(sweep.unread, Some(ViewFailure::NoLayers));
    let observed = sweep.observations();
    assert_eq!(observed.len(), 1);
    assert_eq!(observed[0].role, KeyRole::Enumeration);
    assert_eq!(observed[0].outcome, KeyOutcome::Failed);
}

#[skuld::test]
fn a_sweep_handed_no_view_at_all_is_an_unreadable_enumeration() {
    // `read_layer_views` never returns none, but this function does not rest on that: no view read is no look taken.
    let sweep = sweep_unrecognised(&[], |_| panic!("nothing was enumerated, so nothing is deleted"));
    assert!(sweep.swept.is_empty());
    assert_eq!(sweep.unread, Some(ViewFailure::NoLayers));
    assert_eq!(sweep.observations()[0].role, KeyRole::Enumeration);
}

#[skuld::test]
fn a_clean_enumeration_deletes_and_observes_nothing() {
    // An empty boot-time view after BFE started is not evidence that no record survives, so it must not become a
    // proof: it adds no observation at all.
    let sweep = clean_provider_sweep();
    assert!(sweep.swept.is_empty());
    assert!(sweep.unread.is_none());
    assert!(sweep.observations().is_empty());
}

// What the sweep proves ===============================================================================================

/// A sweep whose every view could not be read.
fn unreadable_provider_sweep() -> ProviderSweep {
    sweep_unrecognised(&[unreadable(other_layer(1), 5)], |_| panic!("nothing to delete"))
}

/// A sweep that found one boot-time stranger and got `code` back from its delete.
fn sweep_deleting_one_stranger(code: u32) -> ProviderSweep {
    sweep_unrecognised(&[Ok(vec![ours_boot_time(stranger(1))])], |_| code)
}

#[skuld::test]
fn a_view_that_could_not_be_read_leaves_a_boot_time_key_unproven() {
    let observed = unreadable_provider_sweep().observations();
    assert_eq!(observed.len(), 1);
    let o = &observed[0];
    assert_eq!(o.lifetime, KeyLifetime::BootTime);
    assert_eq!(o.outcome, KeyOutcome::Failed);
    assert_eq!(o.role, KeyRole::Enumeration);
    assert!(!o.proves_empty());
    assert_eq!(o.key, UNENUMERATED_LABEL);
}

#[skuld::test]
fn an_unrecognised_filter_whose_delete_removed_it_is_a_watched_removal_and_one_that_did_not_is_not() {
    let removed = sweep_deleting_one_stranger(ERROR_SUCCESS.0).observations();
    assert!(removed[0].proves_empty());
    let raced = sweep_deleting_one_stranger(FWP_E_FILTER_NOT_FOUND_DWORD).observations();
    assert!(
        !raced[0].proves_empty(),
        "a boot-time key's not-found proves nothing, however it was found"
    );
}

/// `stranger(1)` as `netsh wfp show boottimepolicy` prints a filter key, written out rather than derived.
const STRANGER_1_AS_NETSH_PRINTS_IT: &str = "{7a110000-0000-4000-8000-000000000001}";

fn mentions<'a>(keys: impl IntoIterator<Item = &'a crate::routing::failclosed::UnprovenKey>, needle: &str) -> bool {
    keys.into_iter().any(|k| k.label().contains(needle))
}

#[skuld::test]
fn a_stranger_is_named_by_the_guid_netsh_prints_for_its_filter() {
    let sweep = sweep_deleting_one_stranger(ERROR_SUCCESS.0);
    let label = &sweep.swept[0].0.label;
    assert!(label.starts_with(UNRECOGNISED_LABEL), "{label}");
    assert!(label.ends_with(STRANGER_1_AS_NETSH_PRINTS_IT), "{label}");
    assert_eq!(sweep.observations()[0].key, *label);
}

#[skuld::test]
fn a_refused_delete_of_an_unrecognised_filter_does_not_fail_the_disengage_and_is_reported() {
    // The code assumes (unmeasured) that a live boot-time filter is not enforced once BFE has started, so a stranger
    // the OS will not let go of blocks nothing now, and failing the sweep over it would keep `bridge unlock` and the
    // tray's Unblock from writing the lockdown intent off: the next start would re-engage the kill switch, a lockout
    // loop over a filter that does nothing at runtime. The refusal is reported instead, by the GUID the operator can
    // match.
    let keys = sweep_answering(FWP_E_FILTER_NOT_FOUND_DWORD, ERROR_SUCCESS.0);
    let outcome = disengage_verdict(&keys, &sweep_deleting_one_stranger(5), ArmingWitness::Unset);
    let clearance = outcome
        .into_result()
        .expect("a refused stranger delete must not fail the unlock");
    // The filter was found, so a record is possible here even though every sibling answered empty.
    assert!(
        mentions(clearance.leftover_keys(), STRANGER_1_AS_NETSH_PRINTS_IT),
        "{:?}",
        pairs(clearance.leftover_keys())
    );
    assert_eq!(clearance.witness_update(), WitnessUpdate::Arm);
}

#[skuld::test]
fn a_refused_stranger_reaches_the_clearance_with_its_guid_and_the_code_the_os_answered() {
    let keys = sweep_answering(FWP_E_FILTER_NOT_FOUND_DWORD, ERROR_SUCCESS.0);
    let clearance = disengage_verdict(&keys, &sweep_deleting_one_stranger(0x8001_0001), ArmingWitness::Unset)
        .into_result()
        .expect("a refused stranger delete must not fail the unlock");
    let refused: Vec<_> = clearance.refused_strangers().collect();
    assert_eq!(
        refused,
        [(
            format!("unrecognised boot-time filter {STRANGER_1_AS_NETSH_PRINTS_IT}").as_str(),
            Some(0x8001_0001)
        )]
    );
    // A stranger the delete removed is none.
    let removed = disengage_verdict(
        &keys,
        &sweep_deleting_one_stranger(ERROR_SUCCESS.0),
        ArmingWitness::Unset,
    )
    .into_result()
    .unwrap();
    assert_eq!(removed.refused_strangers().count(), 0);
}

#[skuld::test(labels = [GLOBAL_NET_STATE])]
fn a_release_all_whose_unrecognised_delete_was_refused_still_releases_both_kinds_and_reports_it() {
    let lockdown = [swept("lockdown filter", FWP_E_FILTER_NOT_FOUND_DWORD)];
    let transient = [swept("transient filter", FWP_E_FILTER_NOT_FOUND_DWORD)];
    let outcome = release_all_verdict(
        &lockdown,
        &transient,
        &sweep_deleting_one_stranger(5),
        ArmingWitness::Unset,
    );
    assert_eq!(outcome.released(), [CoverKind::Lockdown, CoverKind::Transient]);
    let clearance = outcome
        .into_result()
        .expect("a refused stranger delete must not fail the release");
    assert!(
        mentions(clearance.leftover_keys(), STRANGER_1_AS_NETSH_PRINTS_IT),
        "{:?}",
        pairs(clearance.leftover_keys())
    );
}

#[skuld::test]
fn a_refused_delete_of_a_listed_key_still_fails_the_sweep_beside_a_refused_unrecognised_one() {
    // The stranger's refusal is not the listed key's: a listed key is one this build installed and expects to remove.
    let lockdown = [swept("lockdown filter", 5)];
    let transient = [swept("transient filter", FWP_E_FILTER_NOT_FOUND_DWORD)];
    let outcome = release_all_verdict(
        &lockdown,
        &transient,
        &sweep_deleting_one_stranger(5),
        ArmingWitness::Unset,
    );
    assert_eq!(outcome.released(), [CoverKind::Transient]);
    let err = outcome
        .into_result()
        .expect_err("a refused listed key fails the release");
    let text = format!("{err}");
    assert!(text.contains("lockdown filter"), "{text}");
    assert!(!text.contains(STRANGER_1_AS_NETSH_PRINTS_IT), "{text}");

    let keys = sweep_answering(5, ERROR_SUCCESS.0);
    let err = disengage_verdict(&keys, &sweep_deleting_one_stranger(5), ArmingWitness::Unset)
        .into_result()
        .expect_err("a refused listed key fails the disengage");
    assert!(!format!("{err}").contains(STRANGER_1_AS_NETSH_PRINTS_IT), "{err}");
}

#[skuld::test]
fn only_a_listed_key_s_refused_delete_fails_a_sweep() {
    assert!(KeyRole::Plain.refusal_fails_the_sweep());
    assert!(KeyRole::BootTimeSibling.refusal_fails_the_sweep());
    assert!(!KeyRole::Unlisted.refusal_fails_the_sweep());
    assert!(!KeyRole::Enumeration.refusal_fails_the_sweep());
}

#[skuld::test]
fn an_enumeration_failure_is_reported_apart_from_a_delete_failure_and_does_not_fail_the_sweep() {
    // An unreadable view proves nothing is installed OR absent. Failing the escape hatch over it would keep an armed
    // kill switch armed on a host where the enumeration itself is what is broken.
    let keys = sweep_answering(FWP_E_FILTER_NOT_FOUND_DWORD, ERROR_SUCCESS.0);
    let outcome = disengage_verdict(&keys, &unreadable_provider_sweep(), ArmingWitness::Unset);
    let clearance = outcome.clearance().clone();
    assert!(outcome.into_result().is_ok());
    assert!(
        mentions(clearance.leftover_keys(), UNENUMERATED_LABEL),
        "the operator is told the provider sweep could not run: {:?}",
        pairs(clearance.leftover_keys())
    );
    assert_ne!(UNENUMERATED_LABEL, UNRECOGNISED_LABEL);
}

#[skuld::test]
fn an_unreadable_enumeration_reaches_the_operator_report_whatever_the_siblings_and_the_record_say() {
    // Every sibling answered empty and the record is unset: the one cell where nothing else speaks. The docs promise
    // that an unreadable enumeration is reported; it is the only thing here that can say a stranger went unlooked-for.
    let keys = sweep_answering(FWP_E_FILTER_NOT_FOUND_DWORD, FWP_E_FILTER_NOT_FOUND_DWORD);
    let clearance = disengage_verdict(&keys, &unreadable_provider_sweep(), ArmingWitness::Unset)
        .into_result()
        .expect("an unreadable enumeration does not fail the sweep");
    assert_eq!(
        pairs(clearance.leftover_keys()),
        [(UNENUMERATED_LABEL, KeyRole::Enumeration)]
    );
    assert_eq!(pairs(clearance.unenumerated_views()), pairs(clearance.leftover_keys()));
    assert!(clearance.leftover_filters().next().is_none());
    // ...and it is the only thing reported: the unproven twins still say nothing on a host with no cover.
    let quiet = disengage_verdict(&keys, &clean_provider_sweep(), ArmingWitness::Unset)
        .into_result()
        .unwrap();
    assert!(quiet.leftover_keys().next().is_none());
}

#[skuld::test]
fn an_unreadable_view_on_a_host_with_a_standing_cover_arms_the_record() {
    let keys = sweep_answering(FWP_E_FILTER_NOT_FOUND_DWORD, ERROR_SUCCESS.0);
    let outcome = disengage_verdict(&keys, &unreadable_provider_sweep(), ArmingWitness::Unset);
    assert_eq!(outcome.clearance().witness_update(), WitnessUpdate::Arm);
}

#[skuld::test]
fn removing_a_stranger_cannot_retract_the_record_while_a_known_twin_is_unproven() {
    // The twins answered empty (not live this boot), so the record stays; one removed stranger is not "every
    // boot-time key proven".
    let keys = sweep_answering(FWP_E_FILTER_NOT_FOUND_DWORD, ERROR_SUCCESS.0);
    let outcome = disengage_verdict(
        &keys,
        &sweep_deleting_one_stranger(ERROR_SUCCESS.0),
        ArmingWitness::Unset,
    );
    assert_eq!(outcome.clearance().witness_update(), WitnessUpdate::Arm);
}
