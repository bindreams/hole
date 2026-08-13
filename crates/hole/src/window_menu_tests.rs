//! Structural coverage of the app-wide menu, asserted against
//! [`spec`] rather than the Tauri objects [`build`]
//! makes — see this module's parent for why the two are split. These prove
//! what the menu contains; they cannot prove AppKit dispatches Help-search /
//! window-list correctly for `HELP_SUBMENU_ID` / `WINDOW_SUBMENU_ID`, which
//! is native behavior no test in this crate observes.

use super::*;

/// The submenu titled `title`, or a panic naming what is actually there.
fn submenu<'a>(spec: &'a [SubmenuSpec], title: &str) -> &'a SubmenuSpec {
    spec.iter().find(|s| s.text == title).unwrap_or_else(|| {
        let titles: Vec<&str> = spec.iter().map(|s| s.text).collect();
        panic!("menu has no {title:?} submenu; top-level submenus: {titles:?}")
    })
}

/// Every Hole-owned item id in the menu, in order.
fn custom_ids(spec: &[SubmenuSpec]) -> Vec<&'static str> {
    spec.iter()
        .flat_map(|s| s.items.iter())
        .filter_map(|item| match item {
            ItemSpec::Custom { id, .. } => Some(*id),
            _ => None,
        })
        .collect()
}

/// The item in `spec` carrying `id`, or a panic.
fn custom_item<'a>(spec: &'a [SubmenuSpec], id: &str) -> &'a ItemSpec {
    spec.iter()
        .flat_map(|s| s.items.iter())
        .find(|item| matches!(item, ItemSpec::Custom { id: item_id, .. } if *item_id == id))
        .unwrap_or_else(|| panic!("menu has no item with id {id:?}; ids: {:?}", custom_ids(spec)))
}

#[skuld::test]
fn window_menu_wires_well_known_submenu_ids() {
    let spec = spec();

    assert_eq!(
        submenu(&spec, "Help").id,
        Some(tauri::menu::HELP_SUBMENU_ID),
        "the Help submenu must carry Tauri's well-known id for native Help-search wiring"
    );
    submenu(&spec, "File");

    // The Window submenu (and native window-list wiring) is macOS-only —
    // other platforms get a plain File/Help menu built by the OS toolkit.
    #[cfg(target_os = "macos")]
    {
        assert_eq!(
            submenu(&spec, "Window").id,
            Some(tauri::menu::WINDOW_SUBMENU_ID),
            "the Window submenu must carry Tauri's well-known id for native window-list wiring"
        );
        submenu(&spec, "Hole");
        submenu(&spec, "Edit");
        submenu(&spec, "View");
    }
}

#[skuld::test]
fn window_menu_exposes_every_custom_item_id() {
    let spec = spec();

    let mut expected = vec![ID_WINDOW_IMPORT, ID_WINDOW_EXIT, ID_CHECK_UPDATE, ID_COLLECT_LOGS];
    // On macOS "About Hole" is the native app-submenu item, not a Hole-owned
    // Help item — see `spec`.
    #[cfg(not(target_os = "macos"))]
    expected.push(ID_ABOUT);
    #[cfg(target_os = "macos")]
    expected.push(ID_UNINSTALL_HELPER);

    let mut actual = custom_ids(&spec);
    actual.sort_unstable();
    expected.sort_unstable();
    assert_eq!(
        actual, expected,
        "every Hole-owned menu id must be reachable; `handle_event` dispatches on exactly these"
    );
}

#[skuld::test]
fn every_menu_item_id_has_an_action() {
    // An item the user can click that does nothing is exactly the bug this guards against.
    let spec = spec();
    for id in custom_ids(&spec) {
        assert!(
            action(id).is_some(),
            "menu item {id:?} has no action in `window_menu_action`"
        );
    }
}

#[skuld::test]
fn window_menu_has_no_duplicate_custom_ids() {
    // `handle_event` matches on the id alone, so two items
    // sharing one would make its dispatch ambiguous.
    let spec = spec();
    let ids = custom_ids(&spec);
    let mut unique = ids.clone();
    unique.sort_unstable();
    unique.dedup();
    assert_eq!(unique.len(), ids.len(), "duplicate menu item id in {ids:?}");
}

#[skuld::test]
fn window_menu_file_items_own_the_standard_accelerators() {
    // Exit owning Cmd+Q is why the macOS app submenu deliberately has no
    // native Quit item — see `spec`.
    let spec = spec();
    assert_eq!(
        custom_item(&spec, ID_WINDOW_EXIT),
        &ItemSpec::Custom {
            id: ID_WINDOW_EXIT,
            text: "Exit",
            accelerator: Some("CmdOrCtrl+Q"),
        }
    );
    assert_eq!(
        custom_item(&spec, ID_WINDOW_IMPORT),
        &ItemSpec::Custom {
            id: ID_WINDOW_IMPORT,
            text: "Import...",
            accelerator: Some("CmdOrCtrl+O"),
        }
    );
}

#[cfg(target_os = "macos")]
#[skuld::test]
fn macos_menu_offers_about_once_natively() {
    // Regression: a Hole-owned "About Hole" alongside the app submenu's
    // native one showed the user two identical About entries.
    let spec = spec();
    assert!(
        !spec
            .iter()
            .flat_map(|s| s.items.iter())
            .any(|item| matches!(item, ItemSpec::Custom { text, .. } if text.contains("About"))),
        "no Hole-owned item may duplicate the app submenu's native About item on macOS"
    );
    assert!(
        submenu(&spec, "Hole").items.iter().any(|item| matches!(
            item,
            ItemSpec::Predefined {
                kind: Predefined::About,
                ..
            }
        )),
        "the app submenu must carry the native About item"
    );
}

#[cfg(target_os = "macos")]
#[skuld::test]
fn macos_menu_keeps_the_default_editing_items() {
    // Dropping these would take away working undo/copy/paste: macOS
    // dispatches those shortcuts through NSMenu items, not natively in the
    // edit control as Windows/Linux do.
    let spec = spec();
    let edit = submenu(&spec, "Edit");
    for kind in [
        Predefined::Undo,
        Predefined::Redo,
        Predefined::Cut,
        Predefined::Copy,
        Predefined::Paste,
        Predefined::SelectAll,
    ] {
        assert!(
            edit.items
                .iter()
                .any(|item| matches!(item, ItemSpec::Predefined { kind: k, .. } if *k == kind)),
            "the Edit submenu must keep {kind:?}"
        );
    }
}

#[skuld::test]
fn the_menu_is_installed_app_wide() {
    // Nothing links the builder to this module at compile time, so pin the
    // two calls by text — reverting to a per-window attachment or dropping
    // the event registration would otherwise compile and pass everything.
    let main_rs = include_str!("main.rs");
    assert!(
        main_rs.contains(".menu(window_menu::build)"),
        "main.rs must install the menu app-wide via Builder::menu"
    );
    assert!(
        main_rs.contains(".on_menu_event(window_menu::handle_event)"),
        "main.rs must register the menu handler app-wide via Builder::on_menu_event"
    );
}
