// Shared type definitions for the Hole Dashboard UI.

/// Sentinel value of `latency_ms` meaning "validated by a successful proxy
/// start, not by an explicit test run". Mirrors the Rust constant
/// `LATENCY_VALIDATED_ON_CONNECT` in `crates/common/src/protocol.rs`.
export const LATENCY_VALIDATED_ON_CONNECT = 0;

/// Result of a one-shot test run against a `Server`. Mirrors the Rust
/// `ServerTestOutcome` enum in `crates/common/src/protocol.rs`.
export type ServerTestOutcome =
  | { kind: "reachable"; latency_ms: number }
  | { kind: "dns_failed" }
  | { kind: "tcp_refused" }
  | { kind: "tcp_timeout" }
  | { kind: "plugin_start_failed"; detail: string }
  | { kind: "tunnel_handshake_failed" }
  | { kind: "server_cannot_reach_internet" }
  | { kind: "sentinel_mismatch"; detail: string }
  | { kind: "internal_error"; detail: string };

/// Persisted result of the most recent server test. `tested_at` is an
/// RFC3339 string serialized from `time::OffsetDateTime` on the Rust side
/// and parses cleanly into JS `Date`.
export interface ValidationState {
  tested_at: string;
  outcome: ServerTestOutcome;
}

export interface Server {
  id: string;
  name: string;
  server: string;
  server_port: number;
  plugin?: string;
  plugin_opts?: string;
  method: string;
  password: string;
  validation?: ValidationState | null;
}

export interface FilterRule {
  address: string;
  matching: "exactly" | "with_subdomains" | "wildcard" | "subnet";
  action: "proxy" | "bypass" | "block";
}

/// DNS upstream transport. Mirrors the Rust `DnsProtocol` enum in
/// `crates/common/src/config.rs`. Values are snake_case to match the
/// serde representation on the wire.
export type DnsProtocol = "plain_udp" | "plain_tcp" | "tls" | "https";

/// Built-in DNS forwarder configuration. Mirrors the Rust `DnsConfig`
/// struct in `crates/common/src/config.rs`. Saved as part of
/// `Config.dns`; the bridge reads it at proxy start.
export interface DnsConfig {
  enabled: boolean;
  servers: string[];
  protocol: DnsProtocol;
  intercept_udp53: boolean;
}

export interface Config {
  servers: Server[];
  selected_server: string | null;
  filters: FilterRule[];
  local_port: number;
  local_port_http: number;
  start_on_login: boolean;
  proxy_server_enabled: boolean;
  proxy_socks5: boolean;
  proxy_http: boolean;
  on_startup: string;
  theme: string;
  // Required: `get_config` always returns it (AppConfig has no skip
  // attribute), and `toUiSettings` must always send it — the backend
  // rejects a missing field.
  dns: DnsConfig;
  diagnostic_plugin_tap: boolean;
  [key: string]: unknown;
}

/// `Server` minus the backend-owned `validation`. Mirrors the Rust
/// `UiServerEntry` in `crates/hole/src/ui_settings.rs`.
export type UiServer = Omit<Server, "validation">;

/// The settings payload `save_config` accepts. Mirrors the Rust
/// `UiSettings` (#462): backend-owned state (`enabled`,
/// `elevation_prompt_shown`, `servers[].validation`) is not part of the
/// wire type, and the backend rejects unknown keys — send exactly this.
export interface UiSettings {
  servers: UiServer[];
  selected_server: string | null;
  local_port: number;
  filters: FilterRule[];
  start_on_login: boolean;
  on_startup: string;
  theme: string;
  proxy_server_enabled: boolean;
  proxy_socks5: boolean;
  proxy_http: boolean;
  dns: DnsConfig;
  local_port_http: number;
  diagnostic_plugin_tap: boolean;
}

/// A filter rule the bridge compiled and DROPPED (not enforced). `index` is
/// the rule's position in the submitted ruleset, 1:1 with `config.filters`
/// (incl. the default rule at index 0). Mirrors the Rust `InvalidFilter` in
/// `crates/common/src/protocol.rs` (#470).
export interface InvalidFilter {
  index: number;
  error: string;
}

export interface ProxyStatus {
  running: boolean;
  /// Commit seq of the backend's ProxyStateCell at response time. The
  /// frontend applies observations monotonically by this value; see
  /// `applyProxyStateObservation` in `ui/power-button.ts` (#462).
  state_seq: number;
  uptime_secs: number;
  /// Reason for the most recent running transition, when the bridge reported
  /// one (#470). Non-null only on an out-of-band death (the path-free
  /// sentinel); drives the exactly-once death toast.
  error: string | null;
  /// Filter rules the bridge rejected and is NOT enforcing.
  invalid_filters: InvalidFilter[];
  /// `null` when the bridge could not vouch for the capability (a non-Status
  /// poll arm); the UI keeps the last-known value in that case.
  udp_proxy_available: boolean | null;
  ipv6_bypass_available: boolean | null;
}

export interface Metrics {
  bytes_in: number;
  bytes_out: number;
  speed_in_bps: number;
  speed_out_bps: number;
  uptime_secs: number;
}

export interface PublicIpData {
  ip: string;
  country_code: string;
}

export interface DiagnosticsData {
  app: string;
  bridge: string;
  network: string;
  vpn_server: string;
  internet: string;
  [key: string]: string;
}
