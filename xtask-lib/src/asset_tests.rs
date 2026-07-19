use crate::asset::update_asset_suffix;
use crate::bindir::Os;

#[skuld::test]
fn update_asset_suffix_maps_platform_to_extension() {
    assert_eq!(update_asset_suffix(Os::Windows, "amd64"), "windows-amd64.zip");
    assert_eq!(update_asset_suffix(Os::Darwin, "arm64"), "darwin-arm64.tar.gz");
    assert_eq!(update_asset_suffix(Os::Darwin, "amd64"), "darwin-amd64.tar.gz");
}
