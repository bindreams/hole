use schemars::schema::Schema;
use typify::{TypeSpace, TypeSpaceSettings};

fn main() {
    println!("cargo::rerun-if-changed=api/openapi.yaml");

    let yaml_str = std::fs::read_to_string("api/openapi.yaml").unwrap();
    let spec: serde_json::Value = yaml_serde::from_str(&yaml_str).unwrap();

    // Only generate these types (ProxyConfig/ServerEntry are hand-written)
    let schemas = spec["components"]["schemas"].as_object().unwrap();
    let types_to_generate = ["StatusResponse", "ErrorResponse", "EmptyResponse"];

    let ref_types: Vec<(String, Schema)> = types_to_generate
        .iter()
        .map(|name| {
            let schema: Schema = serde_json::from_value(schemas[*name].clone()).unwrap();
            (name.to_string(), schema)
        })
        .collect();

    let mut settings = TypeSpaceSettings::default();
    settings.with_derive("PartialEq".to_string());

    let mut type_space = TypeSpace::new(&settings);
    type_space.add_ref_types(ref_types).unwrap();

    let types_code = type_space.to_stream().to_string();

    // Extract route constants from paths
    let paths = spec["paths"].as_object().unwrap();
    let mut routes = String::new();
    for path in paths.keys() {
        let const_name = path.trim_start_matches("/v1/").to_uppercase();
        routes.push_str(&format!("pub const ROUTE_{const_name}: &str = \"{path}\";\n"));
    }

    let out_dir = std::env::var("OUT_DIR").unwrap();
    std::fs::write(
        std::path::Path::new(&out_dir).join("api_generated.rs"),
        format!("{types_code}\n\n{routes}"),
    )
    .unwrap();
}
