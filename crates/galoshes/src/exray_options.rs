//! Options handed to the embedded ex-ray.

use anyhow::{Context, Result};

const MUX_OFF: &str = "mux=0";

/// Build the embedded ex-ray's `SS_PLUGIN_OPTIONS`, appending `mux=0`.
///
/// galoshes' yamux already collapsed every stream onto one connection, so
/// Mux.Cool has nothing left to multiplex. ex-ray is first-wins, so an earlier
/// `mux=` overrides this; `mux` also picks the server's dokodemo destination.
pub fn ex_ray_options(plugin_options: Option<&str>) -> Result<String> {
    let Some(opts) = plugin_options.filter(|s| !s.is_empty()) else {
        return Ok(MUX_OFF.to_string());
    };
    // In the real galoshes binary this Err is unreachable — `main` validates
    // the same string via `Mode::from_plugin_options` first — but it stays
    // live for direct callers and this module's own unit tests.
    let segments = garter::split_plugin_options(opts).context("cannot build plugin options for the embedded ex-ray")?;
    let out = garter::join_plugin_options(segments.iter().map(|s| s.raw).chain([MUX_OFF]));
    // Contract, not input validation: the split accepts exactly what ex-ray
    // accepts, so a miss means garter's escaping drifted from ex-ray's. Checked
    // on the appended pair, which is always last — an operator's own `mux=`
    // would satisfy a mere presence check while the append was being swallowed.
    debug_assert_eq!(
        garter::parse_plugin_options(&out)
            .expect("well-formed by construction: raw segments already validated by split_plugin_options")
            .last()
            .map(|(k, v)| (k.as_str(), v.as_str())),
        Some(("mux", "0")),
        "appended mux directive vanished: {out:?}"
    );
    Ok(out)
}
