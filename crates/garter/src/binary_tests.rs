use crate::binary::BinaryPlugin;
use crate::plugin::ChainPlugin;

#[skuld::test]
fn binary_plugin_name_from_path() {
    let plugin = BinaryPlugin::new("/usr/bin/v2ray-plugin", None);
    assert_eq!(plugin.name(), "v2ray-plugin");
}

#[skuld::test]
#[cfg(windows)]
fn binary_plugin_name_from_windows_path() {
    let plugin = BinaryPlugin::new(r"C:\plugins\v2ray-plugin.exe", None);
    assert_eq!(plugin.name(), "v2ray-plugin");
}

#[skuld::test]
fn binary_plugin_with_options() {
    let plugin = BinaryPlugin::new("/usr/bin/v2ray-plugin", Some("tls;host=example.com"));
    assert_eq!(plugin.name(), "v2ray-plugin");
}
