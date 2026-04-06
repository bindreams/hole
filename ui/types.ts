// Shared type definitions for the Hole Dashboard UI.

export interface Server {
  id: string;
  name: string;
  server: string;
  server_port: number;
  plugin?: string;
  plugin_opts?: string;
  method: string;
  password: string;
}

export interface FilterRule {
  address: string;
  matching: "exactly" | "with_subdomains" | "wildcard" | "subnet";
  action: "proxy" | "bypass" | "block";
}

export interface Config {
  servers: Server[];
  selected_server: string | null;
  filters: FilterRule[];
  local_port: number;
  start_on_login: boolean;
  proxy_server_enabled: boolean;
  proxy_socks5: boolean;
  proxy_http: boolean;
  on_startup: string;
  theme: string;
  [key: string]: unknown;
}

export interface ProxyStatus {
  running: boolean;
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
