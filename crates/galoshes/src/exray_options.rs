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
    // A rejected string is fatal here because ex-ray does not reject it: it
    // discards every option and reports `ready` on the flag-default port. The
    // reason comes from the error's own Display, which names the shape without
    // echoing options that may carry a secret.
    let segments = garter::split_plugin_options(opts).context("cannot build plugin options for the embedded ex-ray")?;
    let out = garter::join_plugin_options(segments.iter().map(|s| s.raw).chain([MUX_OFF]));
    // Contract, not input validation: the split accepts exactly what ex-ray
    // accepts, so a miss means garter's escaping drifted from ex-ray's. Checked
    // on the appended pair, which is always last — an operator's own `mux=`
    // would satisfy a mere presence check while the append was being swallowed.
    debug_assert_eq!(
        garter::parse_plugin_options(&out)
            .last()
            .map(|(k, v)| (k.as_str(), v.as_str())),
        Some(("mux", "0")),
        "appended mux directive vanished: {out:?}"
    );
    Ok(out)
}
