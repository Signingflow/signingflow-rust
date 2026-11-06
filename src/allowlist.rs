use std::collections::HashMap;
use std::sync::OnceLock;

use serde_json::Value;

#[derive(Debug, Clone)]
pub(crate) struct Operation {
    pub http: String,
    pub path: String,
    pub idempotent: bool,
    pub capability: String,
}

pub(crate) fn operation(id: &str) -> Operation {
    operations().get(id).unwrap_or_else(|| panic!("allowlist missing {id}")).clone()
}

fn operations() -> &'static HashMap<String, Operation> {
    static OPS: OnceLock<HashMap<String, Operation>> = OnceLock::new();
    OPS.get_or_init(|| {
        let doc: Value = serde_json::from_str(include_str!("../resources/allowlist.json")).expect("allowlist");
        let mut map = HashMap::new();
        for item in doc["operations"].as_array().expect("operations") {
            let id = item["operationId"].as_str().expect("id").to_owned();
            map.insert(
                id,
                Operation {
                    http: item["http"].as_str().expect("http").to_owned(),
                    path: item["path"].as_str().expect("path").to_owned(),
                    idempotent: item["idempotent"].as_bool().expect("idempotent"),
                    capability: item["capability"].as_str().expect("capability").to_owned(),
                },
            );
        }
        map
    })
}
