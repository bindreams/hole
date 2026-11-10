//! Measurements for the network reset's open premises (#1112, plan Task 1): what the OS does with the split routes
//! and the pf cover when Hole's own records and adapter are gone. They assert nothing about Hole; each prints
//! `MEASURE[1112] ...` lines that the plan's decisions (P3, the Windows record-less route sweep) are settled from,
//! so nextest keeps their output on success (`.config/nextest.toml`).
//!
//! **Result or "could not measure".** A test that finished printed its `MEASURE[1112]` lines and ended with
//! `MEASURE[1112] ... complete`; read the lines. A test that could not set its experiment up (not elevated, the
//! adapter or the cover refused, a control read disagreed) fails with a `HARNESS: could not measure` panic and
//! printed no verdict. A family (v6) whose add was refused prints `NOT-MEASURED` for that family and carries on:
//! production tolerates that refusal too.
//!
//! **No real split prefix.** `0.0.0.0/1` on an adapter nobody services black-holes the runner. Each experiment
//! takes the production add/delete argv from [`build_setup_commands`]/[`build_split_route_teardown_commands`] and
//! swaps only the destination for a TEST-NET prefix ([`retarget`]), so the tool and the argument shape stay
//! production's while the route cannot catch traffic.
//!
//! Elevated `tun` lane only; names carry `reset_probe_global_net_state_`, matched by the `global_net_state` filter.

#![allow(clippy::disallowed_methods)] // attended test: bare-name host tools (netstat)

use std::net::{IpAddr, Ipv4Addr};

use super::{build_setup_commands, build_split_route_teardown_commands, RouteId};
use crate::gateway::{GatewayInfo, NextHop};
use util::system_tool::SystemTool;

/// The address family of one measured route.
#[derive(Clone, Copy)]
struct Family {
    label: &'static str,
    /// The production split this family's argv comes from.
    id: RouteId,
    split: &'static str,
    /// The TEST-NET prefix swapped in for `split`.
    probe: &'static str,
}

const V4: Family = Family {
    label: "v4",
    id: RouteId::SplitV4Low,
    split: "0.0.0.0/1",
    probe: "198.51.100.0/25",
};
const V6: Family = Family {
    label: "v6",
    id: RouteId::SplitV6Low,
    split: "::/1",
    probe: "2001:db8:1112::/48",
};
const FAMILIES: [Family; 2] = [V4, V6];

/// `args` with the one operand equal to `from` replaced by `to`. Panics when the production argv no longer holds
/// exactly one: the experiment would no longer be the production command.
fn retarget(args: &[String], from: &str, to: &str) -> Vec<String> {
    assert_eq!(
        args.iter().filter(|a| a.as_str() == from).count(),
        1,
        "HARNESS: the production argv no longer names {from} exactly once: {args:?}"
    );
    args.iter()
        .map(|a| if a == from { to.to_string() } else { a.clone() })
        .collect()
}

/// The production install argv for `family` on `tun`, aimed at the probe prefix.
fn add_argv(tun: &str, family: Family) -> (SystemTool, Vec<String>) {
    let gateway = GatewayInfo {
        gateway_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        next_hop: NextHop::Via(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        interface_name: "unused".into(),
        interface_index: 1,
        ipv6_available: true,
    };
    // A loopback server plans no bypass route: the splits are all that is installed.
    let cmd = build_setup_commands(tun, IpAddr::V4(Ipv4Addr::LOCALHOST), &gateway, true)
        .into_iter()
        .find(|c| c.id == family.id)
        .expect("HARNESS: no install command for the split");
    (cmd.tool, retarget(&cmd.args, family.split, family.probe))
}

/// The production delete argv for `family` on `tun`, aimed at the probe prefix.
fn delete_argv(tun: &str, family: Family) -> (SystemTool, Vec<String>) {
    let cmd = build_split_route_teardown_commands(tun)
        .into_iter()
        .find(|c| c.id == family.id)
        .expect("HARNESS: no delete command for the split");
    (cmd.tool, retarget(&cmd.args, family.split, family.probe))
}

fn run(tool: SystemTool, args: &[String]) -> std::process::Output {
    tool.command()
        .and_then(|mut c| c.args(args).output())
        .unwrap_or_else(|e| panic!("HARNESS: could not measure: spawning {tool:?} failed: {e}"))
}

fn line(what: &str, detail: &str) {
    println!("MEASURE[1112] {what} {detail}");
}

// Windows: persistent split routes ====================================================================================

#[cfg(target_os = "windows")]
mod windows_impl {
    use super::{add_argv, delete_argv, line, run, Family, FAMILIES, V4};
    use crate::test_utils::{describe_output, escape::announce, ps_capture, ps_output};
    use crate::{Device, GLOBAL_NET_STATE, TUN};

    /// Not `hole-tun*`, so a production teardown's name sweep cannot delete this adapter mid-test.
    const ADAPTER: &str = "rsetm-hole";
    const V4_CIDR: &str = "10.253.77.1/24";
    const V6_CIDR: &str = "fda6:578a:3baa::1/64";

    /// How one candidate delete is issued after the adapter is gone. The wording and the command are one match each.
    #[derive(Clone, Copy)]
    enum DeleteForm {
        /// The install's own teardown command (no `store=`).
        Production,
        /// The same command with `store=persistent`.
        NetshPersistent,
        /// `Remove-NetRoute` on the persistent store, which needs no interface name.
        RemoveNetRoute,
    }

    impl DeleteForm {
        const ALL: [DeleteForm; 3] = [Self::Production, Self::NetshPersistent, Self::RemoveNetRoute];

        fn label(self) -> &'static str {
            match self {
                Self::Production => "netsh-production-delete",
                Self::NetshPersistent => "netsh-delete-store-persistent",
                Self::RemoveNetRoute => "Remove-NetRoute-PersistentStore",
            }
        }

        /// Issues the delete for `family`; the returned text is what the OS answered.
        fn apply(self, family: Family) -> String {
            match self {
                Self::Production => {
                    let (tool, args) = delete_argv(ADAPTER, family);
                    describe_output(&run(tool, &args))
                }
                Self::NetshPersistent => {
                    let (tool, mut args) = delete_argv(ADAPTER, family);
                    args.push("store=persistent".into());
                    describe_output(&run(tool, &args))
                }
                Self::RemoveNetRoute => match ps_capture(&format!(
                    "Remove-NetRoute -DestinationPrefix '{}' -PolicyStore PersistentStore -Confirm:$false -ErrorAction Stop",
                    family.probe
                )) {
                    Ok(out) => format!("ok stdout={out:?}"),
                    Err(e) => format!("failed {e}"),
                },
            }
        }
    }

    /// The routes to `family`'s probe prefix in one store.
    fn count(family: Family, store: &str) -> usize {
        let text = ps_output(&format!(
            "@(Get-NetRoute -DestinationPrefix '{}' -PolicyStore {store} -ErrorAction SilentlyContinue).Count",
            family.probe
        ));
        text.parse()
            .unwrap_or_else(|_| panic!("HARNESS: could not measure: Get-NetRoute count was {text:?}"))
    }

    fn detail(family: Family, store: &str) -> String {
        ps_output(&format!(
            "(Get-NetRoute -DestinationPrefix '{}' -PolicyStore {store} -ErrorAction SilentlyContinue | \
             Format-List DestinationPrefix,InterfaceAlias,InterfaceIndex,NextHop,Store,State,Publish | Out-String).Trim()",
            family.probe
        ))
    }

    fn adapter_present() -> bool {
        ps_output(&format!(
            "@(Get-NetAdapter -Name '{ADAPTER}' -ErrorAction SilentlyContinue).Count"
        )) != "0"
    }

    /// Removes the adapter and both probe routes from every store. Never panics: it runs on unwind too.
    /// Returns what it could not clear.
    fn restore_host() -> Vec<String> {
        crate::adapter_cleanup::remove_adapter(ADAPTER);
        let mut left = Vec::new();
        for f in FAMILIES {
            let _ = ps_capture(&format!(
                "Remove-NetRoute -DestinationPrefix '{}' -Confirm:$false -ErrorAction SilentlyContinue",
                f.probe
            ));
            for store in ["ActiveStore", "PersistentStore"] {
                match std::panic::catch_unwind(|| count(f, store)) {
                    Ok(0) => {}
                    _ => left.push(format!("{} in {store}", f.probe)),
                }
            }
        }
        if adapter_present() {
            left.push(format!("adapter {ADAPTER}"));
        }
        left
    }

    /// Restores the host on every exit path; announces what it could not clear.
    struct HostGuard;
    impl Drop for HostGuard {
        fn drop(&mut self) {
            let left = restore_host();
            if !left.is_empty() {
                announce(&format!(
                    "HARNESS: the #1112 route probe left {left:?} on this host (TEST-NET routes and a wintun adapter \
                     named {ADAPTER}); remove them by hand"
                ));
            }
        }
    }

    /// One experiment: a fresh adapter with the production install argv applied to both families.
    struct Experiment {
        name: &'static str,
        device: Option<Device>,
        /// The families whose add was accepted.
        added: Vec<Family>,
    }

    impl Experiment {
        fn begin(name: &'static str) -> Self {
            assert!(
                restore_host().is_empty(),
                "HARNESS: could not measure: the host is not clean before `{name}`"
            );
            let mut e = Self {
                name,
                device: None,
                added: Vec::new(),
            };
            e.create_adapter();
            for f in FAMILIES {
                let (tool, args) = add_argv(ADAPTER, f);
                let out = run(tool, &args);
                if !out.status.success() {
                    assert!(
                        f.label != V4.label,
                        "HARNESS: could not measure: the v4 add was refused: {}",
                        describe_output(&out)
                    );
                    line(
                        &format!("windows scenario={name} family={}", f.label),
                        &format!("NOT-MEASURED add refused: {}", describe_output(&out)),
                    );
                    continue;
                }
                // The control: the add the production command made is visible in the live table.
                assert_eq!(
                    count(f, "ActiveStore"),
                    1,
                    "HARNESS: could not measure: the {} route is not in the active store after a successful add",
                    f.label
                );
                e.added.push(f);
            }
            e
        }

        fn create_adapter(&mut self) {
            crate::device::wintun::ensure_loaded().expect("HARNESS: could not measure: wintun.dll must load");
            self.device = Some(
                Device::build(|c| {
                    c.tun_name = ADAPTER.into();
                    c.mtu = 1400;
                    c.ipv4 = Some(V4_CIDR.parse().unwrap());
                    c.ipv6 = Some(V6_CIDR.parse().unwrap());
                })
                .unwrap_or_else(|e| {
                    panic!("HARNESS: could not measure: creating the wintun adapter failed ({e}); not elevated?")
                }),
            );
        }

        fn remove_adapter(&mut self) {
            self.device = None;
            crate::adapter_cleanup::remove_adapter(ADAPTER);
            assert!(
                !adapter_present(),
                "HARNESS: could not measure: the adapter is still present after its removal"
            );
        }

        /// Prints both stores for every added family. The persistent store is the verdict; the active one is context.
        fn report(&self, step: &str) {
            for f in &self.added {
                line(
                    &format!("windows scenario={} family={} step={step}", self.name, f.label),
                    &format!(
                        "active={} persistent={}\n  persistent entry: {}",
                        count(*f, "ActiveStore"),
                        count(*f, "PersistentStore"),
                        detail(*f, "PersistentStore").replace('\n', "\n    "),
                    ),
                );
            }
        }
    }

    /// Persistent split routes: do they outlive the adapter, and which delete removes them (#968).
    #[skuld::test(labels = [TUN, GLOBAL_NET_STATE], serial = TUN)]
    fn reset_probe_global_net_state_windows_persistent_split_routes() {
        let _guard = HostGuard;

        // 1. Nothing deletes the route: does it outlive the adapter?
        let mut e = Experiment::begin("no-delete");
        e.report("adapter-present");
        e.remove_adapter();
        e.report("adapter-removed");
        drop(e);
        assert!(restore_host().is_empty(), "HARNESS: cleanup after `no-delete` failed");

        // 2. The install's own teardown run while the adapter is still there, as a normal stop does.
        let mut e = Experiment::begin("delete-while-present");
        for f in e.added.clone() {
            line(
                &format!("windows scenario=delete-while-present family={}", f.label),
                &format!("netsh-production-delete: {}", DeleteForm::Production.apply(f)),
            );
        }
        e.report("after-delete");
        e.remove_adapter();
        e.report("adapter-removed");
        drop(e);
        assert!(
            restore_host().is_empty(),
            "HARNESS: cleanup after `delete-while-present` failed"
        );

        // 3. Each candidate delete, after the adapter is gone (what a reset or a crash recovery faces).
        for form in DeleteForm::ALL {
            let name = form.label();
            let mut e = Experiment::begin(name);
            e.remove_adapter();
            e.report("adapter-removed");
            for f in e.added.clone() {
                line(
                    &format!("windows scenario={name} family={}", f.label),
                    &format!("{name}: {}", form.apply(f)),
                );
            }
            e.report("after-delete");
            drop(e);
            assert!(restore_host().is_empty(), "HARNESS: cleanup after `{name}` failed");
        }

        // 4. Does the route re-attach when an adapter with the same GUID and name returns?
        let mut e = Experiment::begin("same-guid-returns");
        e.remove_adapter();
        e.report("adapter-removed");
        e.create_adapter();
        e.report("adapter-recreated");
        drop(e);
        assert!(
            restore_host().is_empty(),
            "HARNESS: cleanup after `same-guid-returns` failed"
        );

        line("windows", "complete");
    }
}

// macOS: split routes after the utun closes ===========================================================================

#[cfg(target_os = "macos")]
mod macos_routes {
    use super::{add_argv, delete_argv, line, run, FAMILIES, V4};
    use crate::routing::macos_route_command_succeeded;
    use crate::test_utils::route::netstat_dest;
    use crate::test_utils::{describe_output, escape::announce};
    use crate::{Device, GLOBAL_NET_STATE, TUN};
    use device::TunName;

    use crate::device;

    /// The `netstat -rn` line whose destination is exactly `prefix`, if any.
    fn table_line(prefix: &str, inet6: bool) -> Option<String> {
        let (addr, len) = prefix.split_once('/').expect("HARNESS: a prefix with a length");
        let dest = if inet6 {
            // netstat prints an IPv6 destination in its compressed form with the length.
            prefix.to_string()
        } else {
            format!("{}/{len}", netstat_dest(addr))
        };
        let family = if inet6 { "inet6" } else { "inet" };
        let out = std::process::Command::new("netstat")
            .args(["-rn", "-f", family])
            .output()
            .unwrap_or_else(|e| panic!("HARNESS: could not measure: spawning netstat failed: {e}"));
        assert!(
            out.status.success(),
            "HARNESS: could not measure: netstat failed: {}",
            describe_output(&out)
        );
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .find(|l| l.split_whitespace().next() == Some(dest.as_str()))
            .map(str::to_string)
    }

    /// `route -n get` for the prefix, as evidence beside the table line. A host default route can answer it, so it
    /// is never the verdict.
    fn route_get(prefix: &str, inet6: bool) -> String {
        let mut args = vec!["-n".to_string(), "get".to_string()];
        if inet6 {
            args.push("-inet6".into());
        } else {
            args.push("-net".into());
        }
        args.push(prefix.to_string());
        describe_output(&run(util::system_tool::SystemTool::Route, &args))
    }

    /// Deletes both probe routes with the production delete argv (it names no interface). Never panics.
    fn restore_host() -> Vec<String> {
        let mut left = Vec::new();
        for f in FAMILIES {
            let (tool, args) = delete_argv("unused", f);
            let _ = tool.command().and_then(|mut c| c.args(&args).output());
            if table_line(f.probe, f.label == "v6").is_some() {
                left.push(f.probe);
            }
        }
        left.into_iter().map(str::to_string).collect()
    }

    struct HostGuard;
    impl Drop for HostGuard {
        fn drop(&mut self) {
            let left = std::panic::catch_unwind(restore_host).unwrap_or_default();
            if !left.is_empty() {
                announce(&format!(
                    "HARNESS: the #1112 route probe left TEST-NET routes {left:?} on this host; `route -n delete` them"
                ));
            }
        }
    }

    /// Whether the interface is still in the kernel's name table.
    fn interface_exists(name: &str) -> bool {
        crate::gateway::interface_index_by_name(name).is_ok()
    }

    /// Split routes pointing at a utun: are they still in the table once the utun is gone (P3)?
    #[skuld::test(labels = [TUN, GLOBAL_NET_STATE], serial = TUN)]
    fn reset_probe_global_net_state_macos_split_route_after_utun_close() {
        let _guard = HostGuard;
        for f in FAMILIES {
            assert!(
                table_line(f.probe, f.label == "v6").is_none(),
                "HARNESS: could not measure: a route to {} already exists",
                f.probe
            );
        }

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("HARNESS: build tokio runtime");
        rt.block_on(async {
            let device = Device::build(|c| {
                c.tun_name = TunName::KernelAssigned;
                c.mtu = 1400;
                c.ipv4 = Some("10.253.78.1/24".parse().unwrap());
                c.ipv6 = Some("fda6:578a:3bab::1/64".parse().unwrap());
            })
            .unwrap_or_else(|e| panic!("HARNESS: could not measure: opening a utun failed ({e}); not root?"));
            let tun = device.identity().alias().to_string();

            let mut added = Vec::new();
            for f in FAMILIES {
                let (tool, args) = add_argv(&tun, f);
                let out = run(tool, &args);
                if !macos_route_command_succeeded(&out) {
                    assert!(
                        f.label != V4.label,
                        "HARNESS: could not measure: the v4 add was refused: {}",
                        describe_output(&out)
                    );
                    line(
                        &format!("macos family={}", f.label),
                        &format!("NOT-MEASURED add refused: {}", describe_output(&out)),
                    );
                    continue;
                }
                // The control: the table shows the route on this utun while it is open.
                let before = table_line(f.probe, f.label == "v6").unwrap_or_else(|| {
                    panic!(
                        "HARNESS: could not measure: the {} route is not in the table after a successful add",
                        f.label
                    )
                });
                line(
                    &format!("macos family={} step=utun-open", f.label),
                    &format!("table: {before}"),
                );
                added.push(f);
            }

            // Close the utun, then read once the kernel no longer lists the interface: an uncapped re-check of the
            // real condition, not a bound.
            drop(device);
            while interface_exists(&tun) {
                std::thread::yield_now();
            }
            line("macos", &format!("{tun} left the interface name table"));

            for f in added {
                let after = table_line(f.probe, f.label == "v6");
                line(
                    &format!("macos family={} step=utun-closed", f.label),
                    &match &after {
                        Some(l) => format!("route PRESENT after the utun closed; table: {l}"),
                        None => "route ABSENT after the utun closed".to_string(),
                    },
                );
                line(
                    &format!("macos family={} step=utun-closed", f.label),
                    &format!("route get: {}", route_get(f.probe, f.label == "v6")),
                );
            }
        });
        let left = restore_host();
        assert!(left.is_empty(), "HARNESS: cleanup left {left:?}");
        line("macos", "complete");
    }
}

// macOS: the pf cover with no record ==================================================================================

#[cfg(target_os = "macos")]
mod macos_pf {
    use super::line;
    use crate::device::TunIdentity;
    use crate::routing::{CoverGuard, Routing, SystemRouting};
    use crate::test_utils::describe_output;
    use crate::test_utils::escape::{EscapeGuard, RecordSpec};
    use crate::{GLOBAL_NET_STATE, TUN};
    use util::system_tool::SystemTool;

    const RECORD: RecordSpec = RecordSpec {
        file_name: "hole-reset-probe-pf-RECOVERY.txt",
        what: "hole #1112 pf record-less release probe",
    };

    fn pfctl(args: &[&str]) -> String {
        let out = SystemTool::Pfctl
            .command()
            .and_then(|mut c| c.args(args).output())
            .unwrap_or_else(|e| panic!("HARNESS: could not measure: spawning pfctl failed: {e}"));
        describe_output(&out)
    }

    /// What pf says, read three ways: the label listing the presence read uses, the rules, and the enable state.
    fn pf_view(step: &str) {
        line(
            &format!("macos-pf step={step}"),
            &format!("pfctl -s labels: {}", pfctl(&["-s", "labels"])),
        );
        line(
            &format!("macos-pf step={step}"),
            &format!("pfctl -sr: {}", pfctl(&["-sr"])),
        );
        line(
            &format!("macos-pf step={step}"),
            &format!("pfctl -s info: {}", pfctl(&["-s", "info"])),
        );
    }

    /// Hole's pf cover with its record deleted: does the label still read `Live`, and does reloading `/etc/pf.conf`
    /// clear it (the record-less release the reset would issue)?
    #[skuld::test(labels = [TUN, GLOBAL_NET_STATE], serial = TUN)]
    fn reset_probe_global_net_state_macos_pf_label_without_a_record_is_cleared_by_reloading_default() {
        // The guard releases whatever the test leaves, over the same directory, on every exit path.
        let guard = EscapeGuard::with_temp_dir(&RECORD);
        let dir = guard.state_dir().to_path_buf();
        let routing = SystemRouting::new(dir.clone(), None);
        let server_ip: std::net::IpAddr = "1.1.1.1".parse().unwrap();

        let cover = routing
            .install_lockdown(
                &routing.lock_covers(),
                server_ip,
                &TunIdentity::synthetic(0, "utun-absent"),
                &[],
            )
            .unwrap_or_else(|e| panic!("HARNESS: could not measure: engaging the pf lockdown cover failed: {e}"));
        cover.disarm();

        line(
            "macos-pf step=engaged",
            &format!("presence with its record: {:?}", routing.lockdown_cover_presence()),
        );
        pf_view("engaged");

        // Delete every record the engage wrote, keeping the bytes to put back for the guard's release.
        let mut records = Vec::new();
        for entry in std::fs::read_dir(&dir).expect("HARNESS: read the state dir") {
            let path = entry.expect("HARNESS: dir entry").path();
            if path.extension().is_some_and(|e| e == "json") {
                let bytes = std::fs::read(&path).expect("HARNESS: read a record");
                std::fs::remove_file(&path).expect("HARNESS: delete a record");
                records.push((path, bytes));
            }
        }
        assert!(
            !records.is_empty(),
            "HARNESS: could not measure: the engage wrote no record, so there is nothing to delete"
        );
        line(
            "macos-pf step=record-deleted",
            &format!(
                "deleted {:?}; presence without it: {:?}",
                records.iter().map(|(p, _)| p.file_name().unwrap()).collect::<Vec<_>>(),
                routing.lockdown_cover_presence()
            ),
        );
        pf_view("record-deleted");

        line(
            "macos-pf step=reload-default",
            &format!("pfctl -f /etc/pf.conf: {}", pfctl(&["-f", "/etc/pf.conf"])),
        );
        line(
            "macos-pf step=reload-default",
            &format!("presence after the reload: {:?}", routing.lockdown_cover_presence()),
        );
        pf_view("reload-default");

        // Put the records back so the guard's release finds the pf enable token it must drop.
        for (path, bytes) in records {
            std::fs::write(path, bytes).expect("HARNESS: restore a record");
        }
        drop(guard);
        line("macos-pf", "complete");
    }
}
