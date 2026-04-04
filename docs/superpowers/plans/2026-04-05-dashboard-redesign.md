# Dashboard Redesign Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the plain 600x400 dashboard with a modern 800x600 dark/light themed dashboard featuring live connection stats, a 5-node diagnostic chain, traffic filtering, and expanded settings.

**Architecture:** Backend-first approach — add types and API endpoints first, then rewrite the frontend. New config fields use `#[serde(default)]` for backward compatibility. New daemon endpoints are added to the OpenAPI spec and auto-generated via `build.rs`. The frontend is a complete rewrite of `ui/` (vanilla HTML/CSS/JS, no framework).

**Tech Stack:** Rust (serde, axum, Tauri 2), vanilla HTML/CSS/JS, Inter + Fira Code fonts, CSS custom properties for theming.

**Spec:** `docs/superpowers/specs/2026-04-05-dashboard-redesign.md`
**Reference mockup:** `docs/superpowers/specs/2026-04-05-dashboard-mockup.html`

______________________________________________________________________

## Task 0: Create GitHub issue, branch, and worktree

- [ ] **Step 1: Create a GitHub issue**

```bash
gh issue create --title "Redesign dashboard UI" --body "Implement dashboard redesign per docs/superpowers/specs/2026-04-05-dashboard-redesign.md"
```

Note the issue number (e.g. `96`).

- [ ] **Step 2: Create worktree and branch**

```bash
git worktree add .worktrees/hole-96 -b azhukova/96 main
cd .worktrees/hole-96
```

All subsequent tasks are executed inside this worktree. Do NOT commit to main.

______________________________________________________________________

## Task 1: Add config types (FilterRule, enums, new AppConfig fields)

**Files:**

- Modify: `crates/common/src/config.rs`

- Modify: `crates/common/src/config_tests.rs`

- [ ] **Step 1: Write failing tests for new types**

Add to `crates/common/src/config_tests.rs`:

```rust
// Filter types -----

#[skuld::test]
fn filter_rule_roundtrips_via_json() {
    let rule = FilterRule {
        address: "google.com".to_string(),
        matching: MatchType::WithSubdomains,
        action: FilterAction::Bypass,
    };
    let json = serde_json::to_string(&rule).unwrap();
    let parsed: FilterRule = serde_json::from_str(&json).unwrap();
    assert_eq!(rule, parsed);
}

#[skuld::test]
fn match_type_serializes_as_lowercase() {
    let json = serde_json::to_string(&MatchType::WithSubdomains).unwrap();
    assert_eq!(json, r#""with_subdomains""#);
}

#[skuld::test]
fn filter_action_serializes_as_lowercase() {
    let json = serde_json::to_string(&FilterAction::Bypass).unwrap();
    assert_eq!(json, r#""bypass""#);
}

// New AppConfig fields -----

#[skuld::test]
fn deserialize_old_config_without_new_fields_uses_defaults() {
    let json = r#"{"servers": [], "local_port": 4073, "enabled": false}"#;
    let config: AppConfig = serde_json::from_str(json).unwrap();
    assert!(config.filters.is_empty());
    assert!(!config.start_on_login);
    assert_eq!(config.on_startup, StartupBehavior::RestoreLastState);
    assert_eq!(config.theme, Theme::Dark);
    assert!(config.proxy_server_enabled);
    assert!(config.proxy_socks5);
    assert!(!config.proxy_http);
}

#[skuld::test]
fn new_config_fields_roundtrip(#[fixture(temp_dir)] dir: &Path) {
    let path = dir.join("config.json");
    let config = AppConfig {
        filters: vec![FilterRule {
            address: "*.example.com".to_string(),
            matching: MatchType::Wildcard,
            action: FilterAction::Block,
        }],
        start_on_login: true,
        on_startup: StartupBehavior::AlwaysConnect,
        theme: Theme::Light,
        proxy_server_enabled: false,
        proxy_socks5: false,
        proxy_http: true,
        ..Default::default()
    };
    config.save(&path).unwrap();
    let loaded = AppConfig::load(&path).unwrap();
    assert_eq!(config.filters, loaded.filters);
    assert_eq!(config.start_on_login, loaded.start_on_login);
    assert_eq!(config.on_startup, loaded.on_startup);
    assert_eq!(config.theme, loaded.theme);
    assert_eq!(config.proxy_server_enabled, loaded.proxy_server_enabled);
    assert_eq!(config.proxy_socks5, loaded.proxy_socks5);
    assert_eq!(config.proxy_http, loaded.proxy_http);
}

#[skuld::test]
fn startup_behavior_all_variants_roundtrip() {
    for variant in [
        StartupBehavior::DoNotConnect,
        StartupBehavior::RestoreLastState,
        StartupBehavior::AlwaysConnect,
    ] {
        let json = serde_json::to_string(&variant).unwrap();
        let parsed: StartupBehavior = serde_json::from_str(&json).unwrap();
        assert_eq!(variant, parsed);
    }
}

#[skuld::test]
fn theme_all_variants_roundtrip() {
    for variant in [Theme::Light, Theme::Dark, Theme::System] {
        let json = serde_json::to_string(&variant).unwrap();
        let parsed: Theme = serde_json::from_str(&json).unwrap();
        assert_eq!(variant, parsed);
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p hole-common 2>&1 | head -30`
Expected: compilation errors — types don't exist yet.

- [ ] **Step 3: Implement new types and extend AppConfig**

Add to `crates/common/src/config.rs`, after the `ConfigError` enum (after line 13) and before `AppConfig`:

```rust
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MatchType {
    Exactly,
    WithSubdomains,
    Wildcard,
    Subnet,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FilterAction {
    Proxy,
    Bypass,
    Block,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FilterRule {
    pub address: String,
    pub matching: MatchType,
    pub action: FilterAction,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StartupBehavior {
    DoNotConnect,
    RestoreLastState,
    AlwaysConnect,
}

impl Default for StartupBehavior {
    fn default() -> Self {
        Self::RestoreLastState
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Theme {
    Light,
    Dark,
    System,
}

impl Default for Theme {
    fn default() -> Self {
        Self::Dark
    }
}
```

Add new fields to the `AppConfig` struct (after `elevation_prompt_shown`):

```rust
    pub filters: Vec<FilterRule>,
    pub start_on_login: bool,
    pub on_startup: StartupBehavior,
    pub theme: Theme,
    pub proxy_server_enabled: bool,
    pub proxy_socks5: bool,
    pub proxy_http: bool,
```

Note: the struct-level `#[serde(default)]` uses `AppConfig::default()` to fill all missing fields at once, so field-level `#[serde(default = "...")]` annotations are dead code. All defaults come from the `Default` impl.

The existing `local_port` field serves as the proxy serving port — do NOT add a separate `proxy_port`. The Settings UI label "Serving port" maps to `config.local_port`.

Update `impl Default for AppConfig` to include the new fields:

```rust
    filters: Vec::new(),
    start_on_login: false,
    on_startup: StartupBehavior::default(),
    theme: Theme::default(),
    proxy_server_enabled: true,
    proxy_socks5: true,
    proxy_http: false,
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p hole-common`
Expected: all tests pass, including existing ones (backward compat via `#[serde(default)]`).

- [ ] **Step 5: Commit**

```
git add crates/common/src/config.rs crates/common/src/config_tests.rs
git commit -m "Add FilterRule, MatchType, FilterAction, StartupBehavior, Theme types and extend AppConfig"
```

______________________________________________________________________

## Task 2: Add new OpenAPI schemas and extend code generation

**Files:**

- Modify: `crates/common/api/openapi.yaml`

- Modify: `crates/common/build.rs`

- Modify: `crates/common/src/protocol_tests.rs`

- [ ] **Step 1: Write failing tests for new response types**

Add to `crates/common/src/protocol_tests.rs`:

```rust
// New response types -----

#[skuld::test]
fn metrics_response_roundtrips() {
    let resp = MetricsResponse {
        bytes_in: 1_000_000,
        bytes_out: 500_000,
        speed_in_bps: 1_048_576,
        speed_out_bps: 524_288,
        uptime_secs: 3600,
    };
    let json = serde_json::to_string(&resp).unwrap();
    let parsed: MetricsResponse = serde_json::from_str(&json).unwrap();
    assert_eq!(resp, parsed);
}

#[skuld::test]
fn diagnostics_response_roundtrips() {
    let resp = DiagnosticsResponse {
        app: "ok".to_string(),
        daemon: "ok".to_string(),
        network: "ok".to_string(),
        vpn_server: "ok".to_string(),
        internet: "unknown".to_string(),
    };
    let json = serde_json::to_string(&resp).unwrap();
    let parsed: DiagnosticsResponse = serde_json::from_str(&json).unwrap();
    assert_eq!(resp, parsed);
}

#[skuld::test]
fn public_ip_response_roundtrips() {
    let resp = PublicIpResponse {
        ip: "185.0.0.42".to_string(),
        country_code: "DE".to_string(),
    };
    let json = serde_json::to_string(&resp).unwrap();
    let parsed: PublicIpResponse = serde_json::from_str(&json).unwrap();
    assert_eq!(resp, parsed);
}

#[skuld::test]
fn route_constants_for_new_endpoints_exist() {
    assert_eq!(ROUTE_METRICS, "/v1/metrics");
    assert_eq!(ROUTE_DIAGNOSTICS, "/v1/diagnostics");
    assert_eq!(ROUTE_PUBLIC_IP, "/v1/public-ip");
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p hole-common 2>&1 | head -30`
Expected: compilation errors — types and constants not generated yet.

- [ ] **Step 3: Add schemas to OpenAPI spec**

Add to `crates/common/api/openapi.yaml` — new paths (after `/v1/reload`):

```yaml
  /v1/metrics:
    get:
      summary: Get connection metrics
      operationId: getMetrics
      responses:
        "200":
          description: Current traffic metrics
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/MetricsResponse"

  /v1/diagnostics:
    get:
      summary: Get diagnostic chain status
      operationId: getDiagnostics
      responses:
        "200":
          description: Health status of each component
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/DiagnosticsResponse"

  /v1/public-ip:
    get:
      summary: Get public IP address
      operationId: getPublicIp
      responses:
        "200":
          description: Current public IP and country
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/PublicIpResponse"
```

Add new schemas under `components.schemas` (after `EmptyResponse`):

```yaml
    MetricsResponse:
      type: object
      required:
        - bytes_in
        - bytes_out
        - speed_in_bps
        - speed_out_bps
        - uptime_secs
      properties:
        bytes_in:
          type: integer
          format: uint64
          minimum: 0
        bytes_out:
          type: integer
          format: uint64
          minimum: 0
        speed_in_bps:
          type: integer
          format: uint64
          minimum: 0
        speed_out_bps:
          type: integer
          format: uint64
          minimum: 0
        uptime_secs:
          type: integer
          format: uint64
          minimum: 0

    DiagnosticsResponse:
      type: object
      required:
        - app
        - daemon
        - network
        - vpn_server
        - internet
      properties:
        app:
          type: string
        daemon:
          type: string
        network:
          type: string
        vpn_server:
          type: string
        internet:
          type: string

    PublicIpResponse:
      type: object
      required:
        - ip
        - country_code
      properties:
        ip:
          type: string
        country_code:
          type: string
```

- [ ] **Step 4: Update build.rs to generate the new types**

In `crates/common/build.rs`, update the `types_to_generate` array (line 20):

```rust
    let types_to_generate = [
        "StatusResponse",
        "ErrorResponse",
        "EmptyResponse",
        "MetricsResponse",
        "DiagnosticsResponse",
        "PublicIpResponse",
    ];
```

The route constants are auto-generated from `paths` keys, so `ROUTE_METRICS`, `ROUTE_DIAGNOSTICS`, and `ROUTE_PUBLIC_IP` will appear automatically. Note: the path `/v1/public-ip` will generate `ROUTE_PUBLIC_IP` (with the hyphen converted to underscore by the `to_uppercase()` on the path segment — verify this. If the build script produces `ROUTE_PUBLIC-IP` instead, adjust the path key or the build script logic).

Check the build script's constant name derivation (line 42-43):

```rust
let const_name = path.trim_start_matches("/v1/").to_uppercase();
```

`"public-ip".to_uppercase()` yields `"PUBLIC-IP"`, which is not a valid Rust identifier. Fix the build script to replace hyphens with underscores:

```rust
let const_name = path.trim_start_matches("/v1/").to_uppercase().replace('-', "_");
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test -p hole-common`
Expected: all tests pass.

- [ ] **Step 6: Commit**

```
git add crates/common/api/openapi.yaml crates/common/build.rs crates/common/src/protocol_tests.rs
git commit -m "Add metrics, diagnostics, public-ip OpenAPI schemas and code generation"
```

______________________________________________________________________

## Task 3: Add new DaemonRequest/DaemonResponse variants

**Files:**

- Modify: `crates/common/src/protocol.rs`

- Modify: `crates/common/src/protocol_tests.rs`

- [ ] **Step 1: Write failing tests for new protocol variants**

Add to `crates/common/src/protocol_tests.rs`:

```rust
// Protocol variant roundtrips -----

#[skuld::test]
fn daemon_request_metrics_roundtrips() {
    let req = DaemonRequest::Metrics;
    let json = serde_json::to_string(&req).unwrap();
    let parsed: DaemonRequest = serde_json::from_str(&json).unwrap();
    assert_eq!(req, parsed);
}

#[skuld::test]
fn daemon_request_diagnostics_roundtrips() {
    let req = DaemonRequest::Diagnostics;
    let json = serde_json::to_string(&req).unwrap();
    let parsed: DaemonRequest = serde_json::from_str(&json).unwrap();
    assert_eq!(req, parsed);
}

#[skuld::test]
fn daemon_request_public_ip_roundtrips() {
    let req = DaemonRequest::PublicIp;
    let json = serde_json::to_string(&req).unwrap();
    let parsed: DaemonRequest = serde_json::from_str(&json).unwrap();
    assert_eq!(req, parsed);
}

#[skuld::test]
fn daemon_response_metrics_roundtrips() {
    let resp = DaemonResponse::Metrics {
        bytes_in: 100,
        bytes_out: 50,
        speed_in_bps: 1024,
        speed_out_bps: 512,
        uptime_secs: 60,
    };
    let json = serde_json::to_string(&resp).unwrap();
    let parsed: DaemonResponse = serde_json::from_str(&json).unwrap();
    assert_eq!(resp, parsed);
}

#[skuld::test]
fn daemon_response_diagnostics_roundtrips() {
    let resp = DaemonResponse::Diagnostics {
        app: "ok".to_string(),
        daemon: "ok".to_string(),
        network: "error".to_string(),
        vpn_server: "unknown".to_string(),
        internet: "unknown".to_string(),
    };
    let json = serde_json::to_string(&resp).unwrap();
    let parsed: DaemonResponse = serde_json::from_str(&json).unwrap();
    assert_eq!(resp, parsed);
}

#[skuld::test]
fn daemon_response_public_ip_roundtrips() {
    let resp = DaemonResponse::PublicIp {
        ip: "1.2.3.4".to_string(),
        country_code: "US".to_string(),
    };
    let json = serde_json::to_string(&resp).unwrap();
    let parsed: DaemonResponse = serde_json::from_str(&json).unwrap();
    assert_eq!(resp, parsed);
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p hole-common 2>&1 | head -20`
Expected: compilation errors — new variants don't exist yet.

- [ ] **Step 3: Add variants to DaemonRequest and DaemonResponse**

In `crates/common/src/protocol.rs`, add to `DaemonRequest` (after `Reload`):

```rust
    Metrics,
    Diagnostics,
    PublicIp,
```

Add to `DaemonResponse` (after `Error`):

```rust
    Metrics {
        bytes_in: u64,
        bytes_out: u64,
        speed_in_bps: u64,
        speed_out_bps: u64,
        uptime_secs: u64,
    },
    Diagnostics {
        app: String,
        daemon: String,
        network: String,
        vpn_server: String,
        internet: String,
    },
    PublicIp {
        ip: String,
        country_code: String,
    },
```

- [ ] **Step 4: Fix any downstream compilation errors**

Run: `cargo build --workspace 2>&1 | head -40`

The GUI crate's `DaemonClient::send()` likely has an exhaustive match on `DaemonRequest` — add stub arms for the new variants. Check `crates/gui/src/daemon_client.rs` for the match and add arms that return `Err("not yet implemented")` temporarily. These will be properly implemented in Task 5.

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test -p hole-common`
Expected: all tests pass.

- [ ] **Step 6: Commit**

```
git add crates/common/src/protocol.rs crates/common/src/protocol_tests.rs crates/gui/src/daemon_client.rs
git commit -m "Add Metrics, Diagnostics, PublicIp protocol variants"
```

______________________________________________________________________

## Task 4: Implement daemon handlers for new endpoints

**Files:**

- Modify: `crates/daemon/src/ipc.rs`
- Modify: `crates/daemon/src/ipc_tests.rs`
- Modify: `crates/daemon/src/proxy_manager.rs`

This task adds the 3 new HTTP handlers to the daemon. For the initial implementation:

- `/v1/metrics` returns zeros for `bytes_in`/`bytes_out`/speed (traffic counters require deeper shadowsocks integration — tracked as follow-up). Uptime comes from existing `ProxyManager::uptime_secs()`.

- `/v1/diagnostics` checks daemon state and network connectivity.

- `/v1/public-ip` fetches from an external API with caching.

- [ ] **Step 1: Write failing tests for new handlers**

Study the existing test pattern in `crates/daemon/src/ipc_tests.rs` — it likely uses `IpcServer::bind` with a `MockBackend` and `run_once()`. Write tests following the same pattern for the 3 new endpoints. The exact test code depends on the existing mock infrastructure — the implementing agent should read `ipc_tests.rs` and `proxy_tests.rs` to understand the MockBackend pattern.

Key test cases:

- `metrics_returns_zeros_when_stopped` — GET /v1/metrics when proxy is stopped → uptime_secs=0, bytes=0

- `metrics_returns_uptime_when_running` — start proxy, GET /v1/metrics → uptime_secs > 0

- `diagnostics_shows_daemon_running` — start proxy, GET /v1/diagnostics → daemon="ok"

- `diagnostics_shows_daemon_stopped` — GET /v1/diagnostics without starting → daemon="error"

- `public_ip_returns_response` — GET /v1/public-ip → returns valid JSON (may need to mock the external HTTP call)

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p hole-daemon 2>&1 | head -30`
Expected: compilation errors or test failures.

- [ ] **Step 3: Add handlers and register routes**

In `crates/daemon/src/ipc.rs`, add the import for new response types:

```rust
use hole_common::protocol::{
    // existing imports...
    MetricsResponse, DiagnosticsResponse, PublicIpResponse,
    ROUTE_METRICS, ROUTE_DIAGNOSTICS, ROUTE_PUBLIC_IP,
};
```

Add routes to `build_router` (after the existing `.route()` calls):

```rust
        .route(ROUTE_METRICS, axum::routing::get(handle_metrics::<B>))
        .route(ROUTE_DIAGNOSTICS, axum::routing::get(handle_diagnostics::<B>))
        .route(ROUTE_PUBLIC_IP, axum::routing::get(handle_public_ip::<B>))
```

Add handler implementations:

```rust
async fn handle_metrics<B: ProxyBackend + 'static>(
    State(proxy): State<Arc<Mutex<ProxyManager<B>>>>,
) -> Json<MetricsResponse> {
    let pm = proxy.lock().await;
    Json(MetricsResponse {
        bytes_in: 0,  // TODO: integrate with shadowsocks traffic counters
        bytes_out: 0,
        speed_in_bps: 0,
        speed_out_bps: 0,
        uptime_secs: pm.uptime_secs(),
    })
}

async fn handle_diagnostics<B: ProxyBackend + 'static>(
    State(proxy): State<Arc<Mutex<ProxyManager<B>>>>,
) -> Json<DiagnosticsResponse> {
    let pm = proxy.lock().await;
    let daemon_ok = pm.state() == ProxyState::Running;
    // Network check: attempt to get default gateway via the backend instance.
    // ProxyManager needs a public accessor: `pub fn backend(&self) -> &B`
    let network_ok = pm.backend().default_gateway().is_ok();
    // Cascade: if daemon is down, vpn_server and internet are unknown
    // If network is down, vpn_server and internet are unknown
    let (vpn, internet) = if !daemon_ok {
        ("unknown", "unknown")
    } else if !network_ok {
        ("unknown", "unknown")
    } else {
        // VPN is assumed ok if daemon is running and network is up
        // A more thorough check could ping the server IP
        ("ok", "ok")
    };
    Json(DiagnosticsResponse {
        app: "ok".to_string(),
        daemon: if daemon_ok { "ok" } else { "error" }.to_string(),
        network: if network_ok { "ok" } else { "error" }.to_string(),
        vpn_server: vpn.to_string(),
        internet: internet.to_string(),
    })
}
```

For `handle_public_ip`, the daemon needs to call an external IP service. The IP cache should be stored in axum state (not a global static) so it's testable. Create a new struct to hold both the ProxyManager and the IP cache, or pass the cache as a separate axum state extension.

The simplest approach: add an `IpcState<B>` wrapper struct that holds both `ProxyManager` and the IP cache, and use that as the axum state:

```rust
pub struct IpcState<B: ProxyBackend> {
    pub proxy: Arc<Mutex<ProxyManager<B>>>,
    pub ip_cache: Arc<Mutex<Option<(PublicIpResponse, Instant)>>>,
}
```

Update `build_router` to accept and pass `IpcState<B>` instead of raw `Arc<Mutex<ProxyManager<B>>>`. Update all existing handlers to extract `proxy` from the new state.

For the public IP fetch, use `ureq` v3 with HTTPS. Add `ureq` to `crates/daemon/Cargo.toml`:

```toml
ureq = "3"
```

Also add `Clone` to the generated types. In `crates/common/build.rs`, update settings:

```rust
    settings.with_derive("Clone".to_string());
```

The handler implementation:

```rust
async fn handle_public_ip<B: ProxyBackend + 'static>(
    State(state): State<Arc<IpcState<B>>>,
) -> Result<Json<PublicIpResponse>, (StatusCode, Json<ErrorResponse>)> {
    let mut cached = state.ip_cache.lock().await;

    // Return cached value if fresh (< 60s)
    if let Some((resp, fetched_at)) = cached.as_ref() {
        if fetched_at.elapsed().as_secs() < 60 {
            return Ok(Json(resp.clone()));
        }
    }

    // Fetch via HTTPS
    match tokio::task::spawn_blocking(|| {
        let agent = ureq::Agent::new_with_defaults();
        let body: serde_json::Value = agent
            .get("https://ipinfo.io/json")
            .call()
            .map_err(|e| format!("IP lookup failed: {e}"))?
            .body_mut()
            .read_json()
            .map_err(|e| format!("parse error: {e}"))?;
        Ok::<_, String>(PublicIpResponse {
            ip: body["ip"].as_str().unwrap_or("unknown").to_string(),
            country_code: body["country"].as_str().unwrap_or("??").to_string(),
        })
    })
    .await
    .map_err(|e| format!("task join error: {e}"))
    {
        Ok(Ok(resp)) => {
            *cached = Some((resp.clone(), Instant::now()));
            Ok(Json(resp))
        }
        Ok(Err(e)) | Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { message: e.to_string() }),
        )),
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p hole-daemon`
Expected: all tests pass.

- [ ] **Step 5: Commit**

```
git add crates/daemon/src/ipc.rs crates/daemon/src/ipc_tests.rs crates/daemon/src/proxy_manager.rs crates/daemon/Cargo.toml
git commit -m "Add /v1/metrics, /v1/diagnostics, /v1/public-ip daemon endpoints"
```

______________________________________________________________________

## Task 5: Extend DaemonClient for new endpoints

**Files:**

- Modify: `crates/gui/src/daemon_client.rs`

- Modify: `crates/gui/src/daemon_client_tests.rs`

- [ ] **Step 1: Read existing DaemonClient code**

Read `crates/gui/src/daemon_client.rs` to understand how `send()` maps `DaemonRequest` variants to HTTP calls and parses responses back into `DaemonResponse` variants. The new variants (`Metrics`, `Diagnostics`, `PublicIp`) need the same treatment: map to GET requests on the new routes, parse JSON responses into the corresponding `DaemonResponse` variant.

- [ ] **Step 2: Write failing tests**

Follow the existing test pattern in `daemon_client_tests.rs`. Write tests for:

- `send_metrics_returns_response` — send `DaemonRequest::Metrics`, verify `DaemonResponse::Metrics` fields

- `send_diagnostics_returns_response` — send `DaemonRequest::Diagnostics`, verify fields

- `send_public_ip_returns_response` — send `DaemonRequest::PublicIp`, verify fields

- [ ] **Step 3: Run tests to verify they fail**

Run: `cargo test -p hole-gui -- daemon_client 2>&1 | head -20`

- [ ] **Step 4: Implement the new request/response mappings**

Replace the temporary `Err("not yet implemented")` stubs from Task 3 with real implementations that:

- Send GET requests to `ROUTE_METRICS`, `ROUTE_DIAGNOSTICS`, `ROUTE_PUBLIC_IP`

- Parse the JSON response bodies into `MetricsResponse`, `DiagnosticsResponse`, `PublicIpResponse`

- Map them to the corresponding `DaemonResponse` variants

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test -p hole-gui -- daemon_client`
Expected: all tests pass.

- [ ] **Step 6: Commit**

```
git add crates/gui/src/daemon_client.rs crates/gui/src/daemon_client_tests.rs
git commit -m "Extend DaemonClient with metrics, diagnostics, public-ip support"
```

______________________________________________________________________

## Task 6: Add new Tauri commands

**Files:**

- Modify: `crates/gui/src/commands.rs`

- Modify: `crates/gui/src/commands_tests.rs`

- Modify: `crates/gui/src/main.rs`

- [ ] **Step 1: Write failing tests**

Follow the existing pattern in `commands_tests.rs`. Key test cases:

- `get_metrics_returns_json` — invokes command, verifies JSON structure

- `get_diagnostics_returns_json` — invokes command, verifies JSON structure

- `get_public_ip_when_disconnected_returns_ip` — verify it works without daemon

- [ ] **Step 2: Implement new commands**

Add to `crates/gui/src/commands.rs`. Use `state.daemon_send()` (see `state.rs` and the existing `get_proxy_status` pattern at `commands.rs:111-145`). Return graceful defaults when daemon is unreachable (frontend polls these every 1-5 seconds):

```rust
#[tauri::command]
pub async fn get_metrics(state: State<'_, AppState>) -> Result<serde_json::Value, String> {
    match state.daemon_send(DaemonRequest::Metrics).await {
        Ok(DaemonResponse::Metrics { bytes_in, bytes_out, speed_in_bps, speed_out_bps, uptime_secs }) => {
            Ok(serde_json::json!({
                "bytes_in": bytes_in, "bytes_out": bytes_out,
                "speed_in_bps": speed_in_bps, "speed_out_bps": speed_out_bps,
                "uptime_secs": uptime_secs,
            }))
        }
        // Daemon unreachable or unexpected response — return zeros
        _ => Ok(serde_json::json!({
            "bytes_in": 0, "bytes_out": 0,
            "speed_in_bps": 0, "speed_out_bps": 0,
            "uptime_secs": 0,
        })),
    }
}

#[tauri::command]
pub async fn get_diagnostics(state: State<'_, AppState>) -> Result<serde_json::Value, String> {
    match state.daemon_send(DaemonRequest::Diagnostics).await {
        Ok(DaemonResponse::Diagnostics { app, daemon, network, vpn_server, internet }) => {
            Ok(serde_json::json!({
                "app": app, "daemon": daemon, "network": network,
                "vpn_server": vpn_server, "internet": internet,
            }))
        }
        // Daemon unreachable — all nodes unknown except app
        _ => Ok(serde_json::json!({
            "app": "ok", "daemon": "unknown", "network": "unknown",
            "vpn_server": "unknown", "internet": "unknown",
        })),
    }
}

#[tauri::command]
pub async fn get_public_ip(state: State<'_, AppState>) -> Result<serde_json::Value, String> {
    // Try daemon first (fetches through VPN when connected).
    // Fall back to direct fetch if daemon is unreachable.
    if let Ok(DaemonResponse::PublicIp { ip, country_code }) =
        state.daemon_send(DaemonRequest::PublicIp).await
    {
        return Ok(serde_json::json!({ "ip": ip, "country_code": country_code }));
    }

    // Daemon unreachable — fetch directly from GUI process (shows ISP IP).
    // Uses ureq v3 API (Agent-based, not free functions).
    let result = tokio::task::spawn_blocking(|| {
        let agent = ureq::Agent::new_with_defaults();
        let resp: serde_json::Value = agent
            .get("https://ipinfo.io/json")
            .call()
            .map_err(|e| format!("IP lookup failed: {e}"))?
            .body_mut()
            .read_json()
            .map_err(|e| format!("parse error: {e}"))?;
        Ok::<_, String>(serde_json::json!({
            "ip": resp["ip"].as_str().unwrap_or("unknown"),
            "country_code": resp["country"].as_str().unwrap_or("??"),
        }))
    })
    .await
    .map_err(|e| format!("task join error: {e}"))?;

    result
}
```

Note: Uses `https://ipinfo.io/json` (HTTPS, free tier 50k/month) instead of `http://ip-api.com` (plain HTTP, leaks to network observers). The ureq v3 API uses `Agent::new_with_defaults()` and `agent.get()` — free functions like `ureq::get()` do not exist in v3. Check that `ureq` is in `crates/gui/Cargo.toml` (it should be — it's used elsewhere in the crate).

- [ ] **Step 3: Register commands in main.rs**

In `crates/gui/src/main.rs`, add to the `generate_handler!` macro:

```rust
    commands::get_metrics,
    commands::get_diagnostics,
    commands::get_public_ip,
```

- [ ] **Step 4: Run tests**

Run: `cargo test -p hole-gui -- commands`
Expected: all tests pass.

- [ ] **Step 5: Commit**

```
git add crates/gui/src/commands.rs crates/gui/src/commands_tests.rs crates/gui/src/main.rs
git commit -m "Add get_metrics, get_diagnostics, get_public_ip Tauri commands"
```

______________________________________________________________________

## Task 7: Update window configuration

**Files:**

- Modify: `crates/gui/src/tray.rs`

- [ ] **Step 1: Update window size and resize constraints**

In `crates/gui/src/tray.rs`, in the `open_settings_window` function (around line 618), change:

- `inner_size(600.0, 400.0)` → `inner_size(800.0, 600.0)`

- `min_inner_size(450.0, 300.0)` → `min_inner_size(800.0, 600.0)`

- Add `max_inner_size` with width 800 and a large height (e.g. 800.0, 2000.0) to prevent horizontal resizing while allowing vertical resize. Check Tauri 2 docs for the exact API — it may be `.max_inner_size(800.0, 4096.0)` or similar.

- [ ] **Step 2: Verify the build compiles**

Run: `cargo build -p hole-gui`
Expected: compiles successfully.

- [ ] **Step 3: Commit**

```
git add crates/gui/src/tray.rs
git commit -m "Update dashboard window to 800x600, fixed width, vertical resize only"
```

______________________________________________________________________

## Task 8: Frontend — HTML structure and CSS theming

**Files:**

- Rewrite: `ui/index.html`
- Rewrite: `ui/style.css`
- Create: `ui/fonts/` (Inter + Fira Code font files, bundled locally)

This is the structural foundation. The mockup at `docs/superpowers/specs/2026-04-05-dashboard-mockup.html` is the reference. Extract and organize the inline CSS from the mockup into proper files.

**Frontend file structure:** To avoid a single bloated `main.js`, split the JS into focused modules:

- `ui/main.js` — entry point, state management, config load/save, Tauri event listeners
- `ui/sidebar.js` — power button, graph rendering, stats table, diagnostics chain, IP display
- `ui/filters.js` — filter table rendering, in-place editing, inline dropdowns, drag reorder, test filtering
- `ui/settings.js` — toggle switch component, custom dropdown component, settings section wiring
- `ui/sections.js` — collapsible section slide animation logic
- `ui/servers.js` — server card rendering, selection, deletion, file import

Use ES modules (`type="module"` in the script tag, `import`/`export` between files).

- [ ] **Step 1: Bundle fonts locally**

Download Inter and Fira Code `.woff2` files and place them in `ui/fonts/`. This avoids CDN dependency and CSP issues. Create `@font-face` declarations in `style.css`.

- [ ] **Step 2: Write the HTML shell**

Rewrite `ui/index.html` with the two-panel layout structure from the mockup:

- Main area (left) with 3 collapsible sections: Servers, Filters, Settings

- Sidebar (right) with: status header, graph area, stats table, diagnostics chain, version footer

- No functional JS yet — just the static structure

- [ ] **Step 3: Write the CSS with theme tokens**

Rewrite `ui/style.css` using CSS custom properties. Extract the `[data-theme="dark"]` and `[data-theme="light"]` variable blocks from the mockup. Organize into sections:

- Theme variables

- Base/reset

- Layout (main + sidebar)

- Sidebar components (header, graph, stats, diagnostics, footer)

- Main area sections (collapsible headers, server cards, filter table, settings)

- Interactive components (toggle switches, custom dropdowns, drag states)

- [ ] **Step 4: Verify in browser**

Open `ui/index.html` directly in a browser (won't have Tauri commands, but layout should render). Verify dark and light themes work by toggling `data-theme` attribute in devtools.

- [ ] **Step 5: Commit**

```
git add ui/
git commit -m "Rewrite dashboard HTML/CSS with two-panel layout and dark/light theming"
```

______________________________________________________________________

## Task 9: Frontend — main.js core (state, config, sidebar)

**Files:**

- Rewrite: `ui/main.js`

- [ ] **Step 1: Write the core state management and Tauri integration**

Rewrite `ui/main.js` with:

- State management: `config` object, `dirty` flag, DOM refs

- `loadConfig()` / `saveConfig()` — existing pattern, but now includes new fields

- Power button: wired to `toggle_proxy`, updates sidebar status header

- Status polling: poll `get_proxy_status` every 5 seconds (existing), also poll `get_metrics` every 1 second and `get_diagnostics` every 5 seconds

- IP display: call `get_public_ip` on load and on connect/disconnect events

- Throughput graph: SVG-based rolling graph, 60 data points (1 per second), render download (green) and upload (amber) lines with filled areas

- Stats table: update from `get_metrics` response

- Diagnostics chain: update node colors from `get_diagnostics` response, cascade gray logic

- Version footer: read from `__TAURI__` API or config

- Copy-to-clipboard: on click, use `navigator.clipboard.writeText()`

- [ ] **Step 2: Wire up collapsible sections**

Implement the slide animation for section collapse/expand. Each section header toggles its content clip div.

- [ ] **Step 3: Verify with `npx tauri dev`**

Run: `npx tauri dev`
Expected: dashboard opens at 800x600, sidebar shows status, graph animates (zeros if no daemon), sections collapse/expand.

- [ ] **Step 4: Commit**

```
git add ui/main.js
git commit -m "Implement dashboard JS core: state, sidebar, graph, diagnostics"
```

______________________________________________________________________

## Task 10: Frontend — Servers section

**Files:**

- Modify: `ui/main.js`

- [ ] **Step 1: Implement server rendering and selection**

Add server card rendering (from `config.servers`):

- Radio button selection → `save_config` on change

- Server name, address (Fira Code), plugin badge

- Delete button (cross icon) → removes from config, saves

- Empty state: "Import servers from file" dashed zone

- [ ] **Step 2: Wire up file import**

- Click on import zone → `window.__TAURI__.dialog.open()` with JSON filter

- Drag-and-drop: listen for `tauri://drag-drop` event

- Both call `import_servers_from_file` command, then `loadConfig()` to refresh

- [ ] **Step 3: Verify with `npx tauri dev`**

Test: add servers via import, select different servers, delete servers.

- [ ] **Step 4: Commit**

```
git add ui/main.js
git commit -m "Implement server selection, deletion, and file import in dashboard"
```

______________________________________________________________________

## Task 11: Frontend — Filters section

**Files:**

- Modify: `ui/main.js`
- Modify: `ui/style.css` (if additional styles needed)

This is the most complex frontend task. Implement in sub-steps:

- [ ] **Step 1: Render filter table from config**

Render `config.filters` as table rows with:

- Fixed table layout with `<colgroup>` (48%/22%/22%/8%)

- Drag handle (⠿), address (Fira Code), matching type, action with color wash, delete cross

- Default `*` rule: first row, not editable/deletable/draggable

- Vertical column borders

- [ ] **Step 2: Implement in-place address editing**

- Click address cell → replace `<span>` with `<input>` (bottom-border style)

- Enter/blur → commit, update `config.filters`, save

- Escape → cancel, restore original text

- [ ] **Step 3: Implement inline dropdowns for matching/action**

- Hover shows chevron hint

- Click opens dropdown below cell, click again closes (toggle)

- Click outside closes

- Selection updates config and saves

- Action cell background color updates to match new action

- [ ] **Step 4: Implement drag reorder**

- Pointer events on ⠿ handle (not HTML drag API)

- On pointerdown: snapshot cell widths, lift row to `position: fixed` with shadow

- Insert placeholder `<tr>` with accent border

- On pointermove: update lifted row position, move placeholder using FLIP animation

- On pointerup: insert row at placeholder position, clean up styles

- Default `*` rule cannot be displaced — placeholder never inserts before it

- After reorder: update `config.filters` array order, save

- [ ] **Step 5: Implement "+ Add rule" and test filtering**

- "+ Add rule" click → append new FilterRule with empty address, save, render, focus the new address cell for editing

- Test filtering input: on each keystroke, evaluate all rules top-to-bottom against the input, display matched action and rule

- [ ] **Step 6: Verify with `npx tauri dev`**

Test: add rules, edit in-place, reorder by drag, delete, test filtering input.

- [ ] **Step 7: Commit**

```
git add ui/main.js ui/style.css
git commit -m "Implement filter rules table with in-place editing, drag reorder, and test filtering"
```

______________________________________________________________________

## Task 12: Frontend — Settings section

**Files:**

- Modify: `ui/main.js`

- [ ] **Step 1: Implement toggle switch component**

Reusable function that creates a 36x20px toggle element. On click: toggle class, call a callback. Used for: Start on login, Local proxy server, SOCKS5, HTTP.

- [ ] **Step 2: Implement custom dropdown component**

Reusable function that creates a styled dropdown button + menu. Click button → toggle menu, click option → select + close, click outside → close. Used for: On startup, Theme.

- [ ] **Step 3: Wire up settings to config**

- Start on login → `config.start_on_login` + call Tauri autostart plugin

- On startup → `config.on_startup`

- Theme → `config.theme` + set `document.documentElement.dataset.theme`

- Local proxy server → `config.proxy_server_enabled` + toggle nested muting

- SOCKS5 → `config.proxy_socks5`

- HTTP → `config.proxy_http`

- Serving port → `config.proxy_port`

- All changes call `saveConfig()`

- [ ] **Step 4: Implement System theme option**

System theme: use `window.matchMedia('(prefers-color-scheme: dark)')` to detect OS preference. Listen for changes. When theme is "system", follow the media query.

- [ ] **Step 5: Verify with `npx tauri dev`**

Test: toggle all switches, change dropdowns, verify persistence across window close/reopen.

- [ ] **Step 6: Commit**

```
git add ui/main.js
git commit -m "Implement settings section with toggles, dropdowns, and theme switching"
```

______________________________________________________________________

## Task 13: Integration testing and polish

**Files:**

- Various — bug fixes across all files

- [ ] **Step 1: End-to-end verification**

Run through the verification checklist from the spec:

1. Visual: dark theme default, all sections visible
1. Theme switching persists
1. Server management works
1. Filter rules: add, edit, reorder, delete, test
1. Diagnostics cascade
1. Stats update live
1. IP display correct for both states
1. Settings persist
1. Vertical resize works, horizontal locked

- [ ] **Step 2: Fix any issues found**

Address bugs, visual inconsistencies, or missing functionality.

- [ ] **Step 3: Run full test suite**

Run: `cargo test --workspace`
Expected: all tests pass.

- [ ] **Step 4: Final commit**

Stage only the specific files that were modified during polish. Do not use `git add -A`.

```
git add <specific files modified>
git commit -m "Dashboard redesign: integration fixes and polish"
```

______________________________________________________________________

## Task 14: Open PR and verify CI

- [ ] **Step 1: Push branch and open PR**

```bash
git push -u origin azhukova/<ISSUE-NUMBER>
gh pr create --title "Redesign dashboard UI (#<ISSUE-NUMBER>)" --body "$(cat <<'EOF'
## Summary
- Complete dashboard UI redesign: dark/light theme, right sidebar with live stats/graph/diagnostics, left main area with collapsible Servers/Filters/Settings sections
- New daemon API endpoints: /v1/metrics, /v1/diagnostics, /v1/public-ip
- New config types: FilterRule, MatchType, FilterAction, StartupBehavior, Theme
- Traffic filter rules with in-place editing, drag reorder, and test filtering
- Expanded settings: startup behavior, theme, proxy server config

## Test plan
- [ ] Run `cargo test --workspace` — all tests pass
- [ ] Run `npx tauri dev` — dashboard opens at 800x600, dark theme
- [ ] Toggle Connect/Disconnect — sidebar updates, diagnostics chain updates
- [ ] Switch theme in Settings — live update, persists
- [ ] Add/edit/reorder/delete filter rules
- [ ] Import servers from file
- [ ] Verify vertical-only resize
EOF
)"
```

- [ ] **Step 2: Verify CI passes**

```bash
gh pr checks --watch
```

Expected: all CI checks pass. If any fail, fix and push again.
