//! The dashboard's app-wide menu bar.
//!
//! Split in two: [`spec`] describes the menu as plain data, and
//! [`build`] is an interpreter that turns that description into
//! Tauri menu objects, contributing no content of its own.
//!
//! The split is what makes the menu's structure testable. On macOS `muda`
//! (under `tauri::menu::{Menu, Submenu}`) panics unless it is constructed on
//! the real AppKit main thread, and tests do not run there: nextest passes
//! `--nocapture`, so skuld leaves `test_threads` unset and libtest-mimic runs
//! every test on a worker thread. `tauri::test`'s mock runtime does not help
//! — its `run_on_main_thread` runs the closure inline on the caller's thread.
//! Same shape as `dock_icon.rs`, which likewise keeps its main-thread-only
//! call out of the tested functions.

use tauri::menu::{IsMenuItem, Menu, MenuEvent, MenuItem, PredefinedMenuItem, Submenu};
use tauri::AppHandle;
use tracing::info;

use crate::tray::{exit_app, handle_check_for_updates, handle_collect_logs};

const ID_WINDOW_IMPORT: &str = "window_import";
const ID_WINDOW_EXIT: &str = "window_exit";
#[cfg(target_os = "macos")]
const ID_UNINSTALL_HELPER: &str = "uninstall_helper";
/// macOS has no Hole-owned About item — the app submenu's native one covers it.
#[cfg(not(target_os = "macos"))]
const ID_ABOUT: &str = "about";
const ID_CHECK_UPDATE: &str = "check_update";
const ID_COLLECT_LOGS: &str = "window_collect_logs";

/// An OS-provided menu item, named after the `PredefinedMenuItem` constructor
/// that builds it. macOS-only: the Windows/Linux menu is all Hole-owned items.
#[cfg(target_os = "macos")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Predefined {
    About,
    Services,
    Hide,
    HideOthers,
    Undo,
    Redo,
    Cut,
    Copy,
    Paste,
    SelectAll,
    Fullscreen,
    Minimize,
    Maximize,
    CloseWindow,
}

/// One entry in a submenu.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ItemSpec {
    /// A Hole-owned item, dispatched by `id` in `handle_event`.
    Custom {
        id: &'static str,
        text: &'static str,
        accelerator: Option<&'static str>,
    },
    Separator,
    /// `text` overrides the platform's default label when `Some`.
    #[cfg(target_os = "macos")]
    Predefined {
        kind: Predefined,
        text: Option<&'static str>,
    },
}

/// What a Hole-owned menu item does when clicked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Action {
    Import,
    Exit,
    CheckUpdate,
    CollectLogs,
    /// macOS shows the native `Predefined::About` instead.
    #[cfg(not(target_os = "macos"))]
    About,
    #[cfg(target_os = "macos")]
    UninstallHelper,
}

/// The action `id` triggers, or `None` for an id Hole does not own —
/// predefined items are dispatched by the OS, never by
/// `handle_event`.
///
/// Split out of the handler so the tests can prove every [`ItemSpec::Custom`]
/// in [`spec`] maps to an action: an item the user can click that
/// does nothing is the exact failure this guards against.
pub(crate) fn action(id: &str) -> Option<Action> {
    Some(match id {
        ID_WINDOW_IMPORT => Action::Import,
        ID_WINDOW_EXIT => Action::Exit,
        ID_CHECK_UPDATE => Action::CheckUpdate,
        ID_COLLECT_LOGS => Action::CollectLogs,
        #[cfg(not(target_os = "macos"))]
        ID_ABOUT => Action::About,
        #[cfg(target_os = "macos")]
        ID_UNINSTALL_HELPER => Action::UninstallHelper,
        _ => return None,
    })
}

/// One top-level submenu.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SubmenuSpec {
    /// Tauri's well-known id (`HELP_SUBMENU_ID` / `WINDOW_SUBMENU_ID`) when
    /// macOS's menu install must look this submenu up to wire native
    /// Help-search / window-list behavior; `None` for an ordinary submenu.
    pub id: Option<&'static str>,
    pub text: &'static str,
    pub items: Vec<ItemSpec>,
}

/// The menu Hole installs, as plain data.
///
/// On macOS this mirrors `tauri::menu::Menu::default()`'s layout (app submenu,
/// Edit, View, Window) merged with Hole's own File/Help rather than replacing
/// it outright: dropping those submenus would take away working
/// copy/paste/undo/hide/minimize, which macOS dispatches through NSMenu items
/// rather than natively in the edit control as Windows/Linux do. A native
/// `Predefined::Quit` is deliberately absent — File > Exit already owns
/// Cmd+Q and runs the app's graceful `exit_app` shutdown (bridge stop
/// included), so adding one would double-bind that accelerator.
pub(crate) fn spec() -> Vec<SubmenuSpec> {
    let file = SubmenuSpec {
        id: None,
        text: "File",
        items: vec![
            ItemSpec::Custom {
                id: ID_WINDOW_IMPORT,
                text: "Import...",
                accelerator: Some("CmdOrCtrl+O"),
            },
            ItemSpec::Separator,
            ItemSpec::Custom {
                id: ID_WINDOW_EXIT,
                text: "Exit",
                accelerator: Some("CmdOrCtrl+Q"),
            },
        ],
    };

    let check_update = ItemSpec::Custom {
        id: ID_CHECK_UPDATE,
        text: "Check for Updates...",
        accelerator: None,
    };
    let collect_logs = ItemSpec::Custom {
        id: ID_COLLECT_LOGS,
        text: "Collect Logs...",
        accelerator: None,
    };
    // macOS gets its own native "About Hole" from the app submenu below, so
    // Help must not duplicate it there — Windows/Linux have no app submenu,
    // so Help is the only place for it.
    #[cfg(target_os = "macos")]
    let help_items = vec![check_update, collect_logs];
    #[cfg(not(target_os = "macos"))]
    let help_items = vec![
        check_update,
        collect_logs,
        ItemSpec::Custom {
            id: ID_ABOUT,
            text: "About Hole",
            accelerator: None,
        },
    ];
    // `HELP_SUBMENU_ID`: macOS's menu install looks this id up to register the
    // submenu as NSApp's Help menu (search field + keyboard search); without
    // it the items still show but lose that native behavior.
    let help = SubmenuSpec {
        id: Some(tauri::menu::HELP_SUBMENU_ID),
        text: "Help",
        items: help_items,
    };

    #[cfg(not(target_os = "macos"))]
    {
        vec![file, help]
    }

    #[cfg(target_os = "macos")]
    {
        vec![
            SubmenuSpec {
                id: None,
                text: "Hole",
                items: vec![
                    ItemSpec::Predefined {
                        kind: Predefined::About,
                        // Explicit text: Tauri's default falls back to the
                        // Cargo package name ("hole"), not the "Hole" product
                        // name used everywhere else in the app.
                        text: Some("About Hole"),
                    },
                    ItemSpec::Separator,
                    ItemSpec::Custom {
                        id: ID_UNINSTALL_HELPER,
                        text: "Uninstall Helper...",
                        accelerator: None,
                    },
                    ItemSpec::Separator,
                    ItemSpec::Predefined {
                        kind: Predefined::Services,
                        text: None,
                    },
                    ItemSpec::Separator,
                    ItemSpec::Predefined {
                        kind: Predefined::Hide,
                        text: Some("Hide Hole"),
                    },
                    ItemSpec::Predefined {
                        kind: Predefined::HideOthers,
                        text: None,
                    },
                ],
            },
            SubmenuSpec {
                id: None,
                text: "Edit",
                items: vec![
                    ItemSpec::Predefined {
                        kind: Predefined::Undo,
                        text: None,
                    },
                    ItemSpec::Predefined {
                        kind: Predefined::Redo,
                        text: None,
                    },
                    ItemSpec::Separator,
                    ItemSpec::Predefined {
                        kind: Predefined::Cut,
                        text: None,
                    },
                    ItemSpec::Predefined {
                        kind: Predefined::Copy,
                        text: None,
                    },
                    ItemSpec::Predefined {
                        kind: Predefined::Paste,
                        text: None,
                    },
                    ItemSpec::Predefined {
                        kind: Predefined::SelectAll,
                        text: None,
                    },
                ],
            },
            file,
            SubmenuSpec {
                id: None,
                text: "View",
                items: vec![ItemSpec::Predefined {
                    kind: Predefined::Fullscreen,
                    text: None,
                }],
            },
            // `WINDOW_SUBMENU_ID`: macOS's menu install looks this id up to
            // register the submenu as NSApp's Window menu (native window list).
            SubmenuSpec {
                id: Some(tauri::menu::WINDOW_SUBMENU_ID),
                text: "Window",
                items: vec![
                    ItemSpec::Predefined {
                        kind: Predefined::Minimize,
                        text: None,
                    },
                    ItemSpec::Predefined {
                        kind: Predefined::Maximize,
                        text: None,
                    },
                    ItemSpec::Separator,
                    ItemSpec::Predefined {
                        kind: Predefined::CloseWindow,
                        text: None,
                    },
                ],
            },
            help,
        ]
    }
}

/// Build [`spec`] into Tauri menu objects. Installed once,
/// app-wide, via `Builder::menu` in `main.rs` — macOS menus are app-wide
/// (`AppHandle::set_menu`), not per-window, so a per-window-scoped menu is
/// silently ignored there.
pub(crate) fn build<R: tauri::Runtime>(app: &AppHandle<R>) -> tauri::Result<Menu<R>> {
    let mut submenus = Vec::new();
    for spec in spec() {
        let items = spec
            .items
            .iter()
            .map(|item| build_item(app, item))
            .collect::<tauri::Result<Vec<_>>>()?;
        let item_refs: Vec<&dyn IsMenuItem<R>> = items.iter().map(|item| &**item).collect();
        submenus.push(match spec.id {
            Some(id) => Submenu::with_id_and_items(app, id, spec.text, true, &item_refs)?,
            None => Submenu::with_items(app, spec.text, true, &item_refs)?,
        });
    }

    let submenu_refs: Vec<&dyn IsMenuItem<R>> = submenus.iter().map(|s| s as &dyn IsMenuItem<R>).collect();
    Menu::with_items(app, &submenu_refs)
}

fn build_item<R: tauri::Runtime>(app: &AppHandle<R>, spec: &ItemSpec) -> tauri::Result<Box<dyn IsMenuItem<R>>> {
    Ok(match spec {
        ItemSpec::Custom { id, text, accelerator } => Box::new(MenuItem::with_id(app, *id, text, true, *accelerator)?),
        ItemSpec::Separator => Box::new(PredefinedMenuItem::separator(app)?),
        #[cfg(target_os = "macos")]
        ItemSpec::Predefined { kind, text } => build_predefined(app, *kind, *text)?,
    })
}

#[cfg(target_os = "macos")]
fn build_predefined<R: tauri::Runtime>(
    app: &AppHandle<R>,
    kind: Predefined,
    text: Option<&str>,
) -> tauri::Result<Box<dyn IsMenuItem<R>>> {
    let item = match kind {
        Predefined::About => {
            // Version only: the app name and icon already come from the
            // bundle, and Hole has no copyright/credits line to show.
            // (`authors`, `comments`, `license`, `website` and
            // `website_label` would be ignored here regardless — muda
            // documents those as macOS-unsupported.)
            let metadata = tauri::menu::AboutMetadata {
                version: Some(hole::version::VERSION.to_string()),
                ..Default::default()
            };
            PredefinedMenuItem::about(app, text, Some(metadata))?
        }
        Predefined::Services => PredefinedMenuItem::services(app, text)?,
        Predefined::Hide => PredefinedMenuItem::hide(app, text)?,
        Predefined::HideOthers => PredefinedMenuItem::hide_others(app, text)?,
        Predefined::Undo => PredefinedMenuItem::undo(app, text)?,
        Predefined::Redo => PredefinedMenuItem::redo(app, text)?,
        Predefined::Cut => PredefinedMenuItem::cut(app, text)?,
        Predefined::Copy => PredefinedMenuItem::copy(app, text)?,
        Predefined::Paste => PredefinedMenuItem::paste(app, text)?,
        Predefined::SelectAll => PredefinedMenuItem::select_all(app, text)?,
        Predefined::Fullscreen => PredefinedMenuItem::fullscreen(app, text)?,
        Predefined::Minimize => PredefinedMenuItem::minimize(app, text)?,
        Predefined::Maximize => PredefinedMenuItem::maximize(app, text)?,
        Predefined::CloseWindow => PredefinedMenuItem::close_window(app, text)?,
    };
    Ok(Box::new(item))
}

// Event handling ======================================================================================================

/// Handle a click on the dashboard's menu bar. Separate from the tray
/// icon's handler, which dispatches an entirely different id space.
/// Registered once via `Builder::on_menu_event` (app-scoped, not
/// per-window) because macOS menus are app-wide — a window-scoped
/// handler is never reached there.
pub(crate) fn handle_event(app: &AppHandle, event: MenuEvent) {
    // Predefined items are dispatched by the OS and reach here as `None`.
    let Some(action) = action(event.id().as_ref()) else {
        return;
    };
    match action {
        Action::Import => {
            info!("menu: import requested");
            // Deliberately does NOT open the dashboard first. Opening one
            // here would create a webview that has not yet registered its
            // listeners, and the import's outcome event could then land
            // before it was listening. This menu is only reachable from an
            // open dashboard anyway (macOS runs `Accessory` — no menu bar —
            // until one opens, and elsewhere the menu belongs to the
            // window), so there is a listener already.
            crate::import_dialog::pick_and_import(app);
        }
        Action::Exit => {
            info!("menu: exit requested");
            let app_handle = app.clone();
            tauri::async_runtime::spawn(async move { exit_app(app_handle).await });
        }
        Action::CheckUpdate => {
            info!("menu: check for updates");
            let app_handle = app.clone();
            tauri::async_runtime::spawn(async move {
                handle_check_for_updates(app_handle).await;
            });
        }
        Action::CollectLogs => {
            info!("menu: collect logs");
            let app_handle = app.clone();
            tauri::async_runtime::spawn(async move {
                handle_collect_logs(app_handle).await;
            });
        }
        #[cfg(not(target_os = "macos"))]
        Action::About => {
            info!("menu: about dialog");
            use tauri_plugin_dialog::DialogExt;
            // spawn_blocking: blocking_show must not run on the main thread
            // and would park a core async worker if spawned there instead.
            // Its JoinHandle is awaited rather than dropped, so a panic in
            // the dialog crate is reported instead of vanishing.
            let app_handle = app.clone();
            tauri::async_runtime::spawn(async move {
                let shown = tauri::async_runtime::spawn_blocking(move || {
                    app_handle
                        .dialog()
                        .message(format!("Hole {}", hole::version::VERSION))
                        .title("About Hole")
                        .blocking_show();
                });
                if let Err(e) = shown.await {
                    // Fully qualified: `warn` is reachable only from this
                    // non-macOS arm, so an import would be unused on macOS.
                    tracing::warn!(error = %e, "menu: about dialog failed");
                }
            });
        }
        #[cfg(target_os = "macos")]
        Action::UninstallHelper => {
            info!("menu: uninstall helper requested");
            let app_handle = app.clone();
            tauri::async_runtime::spawn(async move {
                crate::tray::handle_uninstall_helper(app_handle).await;
            });
        }
    }
}

#[cfg(test)]
#[path = "window_menu_tests.rs"]
mod window_menu_tests;
