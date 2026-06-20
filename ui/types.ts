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

/// Result of evaluating the Test box input through the bridge filter engine.
/// Mirrors the Rust `FilterEvaluation` in `crates/hole/src/commands.rs`.
export interface FilterEvaluation {
  action: "proxy" | "bypass" | "block";
  /// Index into config.filters of the matched rule; null = terminal fallback
  /// (no rule matched, proxied by default).
  rule_index: number | null;
  matched_address: string | null;
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
}

export interface Config {
  servers: Server[];
  selected_server: string | null;
  filters: FilterRule[];
  local_port: number;
  local_port_http: number;
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
  on_startup: string;
  theme: string;
  proxy_server_enabled: boolean;
  proxy_socks5: boolean;
  proxy_http: boolean;
  dns: DnsConfig;
  local_port_http: number;
  diagnostic_plugin_tap: boolean;
}

export interface ProxyStatus {
  running: boolean;
  /// Commit seq of the backend's ProxyStateCell at response time. The
  /// frontend applies observations monotonically by this value; see
  /// `applyProxyStateObservation` in `ui/power-button.ts` (#462).
  state_seq: number;
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
