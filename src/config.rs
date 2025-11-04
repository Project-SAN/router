use crate::hornet::{routing, types as hornet_types};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

#[derive(Debug, Clone, Serialize)]
pub struct RouterConfig {
    pub mode: String,
    pub debug_level: String,
    pub config_path: PathBuf,
    pub devices: Vec<DeviceConfig>,
    pub routes: Vec<RouteConfig>,
    pub hornet: Option<HornetConfig>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DeviceConfig {
    pub name: String,
    pub enabled: bool,
    pub ignore: bool,
    pub mac: Option<[u8; 6]>,
    pub ipv4: Vec<Ipv4Network>,
    pub mtu: Option<u32>,
    pub nat: Option<DeviceNatConfig>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DeviceNatConfig {
    pub role: NatRole,
    pub outside_ip: Option<Ipv4Addr>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum NatRole {
    Inside,
    Outside,
}

#[derive(Debug, Clone, Serialize)]
pub struct RouteConfig {
    pub destination: Ipv4Network,
    pub next_hop: Option<Ipv4Addr>,
    pub interface: Option<String>,
    pub metric: Option<u32>,
}

#[derive(Debug, Clone, Serialize)]
pub struct HornetConfig {
    pub enabled: bool,
    pub listen_addr: IpAddr,
    pub listen_port: u16,
    pub node_secret_path: Option<PathBuf>,
    pub sv_seed_hex: Option<String>,
    pub directory_file: Option<PathBuf>,
    pub directory_secret_hex: Option<String>,
    pub policy_cache_ttl: u64,
    #[serde(skip_serializing)]
    pub policy_routes: Vec<HornetPolicyRoute>,
}

#[derive(Clone)]
pub struct HornetPolicyRoute {
    pub policy_id: [u8; 32],
    pub segment: hornet_types::RoutingSegment,
    pub interface: Option<String>,
}

impl fmt::Debug for HornetPolicyRoute {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let segment_len = self.segment.0.len();
        f.debug_struct("HornetPolicyRoute")
            .field("policy_id", &hex_encode_bytes(&self.policy_id))
            .field("segment_len", &segment_len)
            .field("interface", &self.interface)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Ipv4Network {
    pub address: Ipv4Addr,
    pub prefix: u8,
}

#[derive(Debug, Clone, Default)]
pub struct CliOverrides {
    pub mode: Option<String>,
    pub debug_level: Option<String>,
}

#[derive(Debug)]
pub enum ConfigError {
    Io(std::io::Error),
    Parse(serde_yaml::Error),
    MissingField(&'static str),
    InvalidValue(String),
    AlreadyInitialized,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::Io(e) => write!(f, "I/O error: {}", e),
            ConfigError::Parse(e) => write!(f, "parse error: {}", e),
            ConfigError::MissingField(name) => write!(f, "missing required field `{}`", name),
            ConfigError::InvalidValue(msg) => write!(f, "invalid value: {}", msg),
            ConfigError::AlreadyInitialized => write!(f, "configuration already initialized"),
        }
    }
}

impl std::error::Error for ConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ConfigError::Io(e) => Some(e),
            ConfigError::Parse(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for ConfigError {
    fn from(value: std::io::Error) -> Self {
        ConfigError::Io(value)
    }
}

impl From<serde_yaml::Error> for ConfigError {
    fn from(value: serde_yaml::Error) -> Self {
        ConfigError::Parse(value)
    }
}

static ROUTER_CONFIG: OnceLock<RouterConfig> = OnceLock::new();

pub fn init_router_config<P: AsRef<Path>>(
    path: P,
    overrides: CliOverrides,
) -> Result<&'static RouterConfig, ConfigError> {
    if let Some(cfg) = ROUTER_CONFIG.get() {
        return Ok(cfg);
    }

    let path_ref = path.as_ref();
    let raw = load_raw_config(path_ref)?;
    let router_config = RouterConfig::from_raw(raw, overrides, path_ref)?;
    ROUTER_CONFIG
        .set(router_config)
        .map_err(|_| ConfigError::AlreadyInitialized)?;
    Ok(ROUTER_CONFIG.get().expect("config just initialized"))
}

pub fn get_router_config() -> Option<&'static RouterConfig> {
    ROUTER_CONFIG.get()
}

impl RouterConfig {
    fn from_raw(
        raw: RawRouterConfig,
        overrides: CliOverrides,
        path: &Path,
    ) -> Result<Self, ConfigError> {
        let mode = overrides
            .mode
            .or(raw.mode)
            .unwrap_or_else(|| "router".to_string());
        let debug_level = overrides
            .debug_level
            .or(raw.debug_level)
            .unwrap_or_else(|| "info".to_string());

        let mut devices = Vec::with_capacity(raw.devices.len());
        for dev in raw.devices {
            devices.push(DeviceConfig::from_raw(dev)?);
        }

        let mut routes = Vec::with_capacity(raw.routes.len());
        for route in raw.routes {
            routes.push(RouteConfig::from_raw(route)?);
        }

        let hornet = raw.hornet.map(HornetConfig::from_raw).transpose()?;

        Ok(Self {
            mode,
            debug_level,
            config_path: path.to_path_buf(),
            devices,
            routes,
            hornet,
        })
    }
}

impl DeviceConfig {
    fn from_raw(raw: RawDeviceConfig) -> Result<Self, ConfigError> {
        let mut ipv4 = Vec::with_capacity(raw.ipv4.len());
        for cidr in raw.ipv4 {
            ipv4.push(parse_ipv4_network(&cidr)?);
        }

        let mac = match raw.mac {
            Some(m) => Some(parse_mac_address(&m)?),
            None => None,
        };

        let nat = match raw.nat {
            Some(n) => Some(DeviceNatConfig::from_raw(n)?),
            None => None,
        };

        Ok(Self {
            name: raw.name,
            enabled: raw.enabled,
            ignore: raw.ignore,
            mac,
            ipv4,
            mtu: raw.mtu,
            nat,
        })
    }
}

impl DeviceNatConfig {
    fn from_raw(raw: RawDeviceNatConfig) -> Result<Self, ConfigError> {
        let outside_ip = match raw.outside_ip {
            Some(addr) => Some(parse_ipv4_addr(&addr)?),
            None => None,
        };
        Ok(Self {
            role: raw.role.into(),
            outside_ip,
        })
    }
}

impl RouteConfig {
    fn from_raw(raw: RawRouteConfig) -> Result<Self, ConfigError> {
        let destination = parse_ipv4_network(&raw.destination)?;
        let next_hop = match raw.next_hop {
            Some(addr) => Some(parse_ipv4_addr(&addr)?),
            None => None,
        };
        Ok(Self {
            destination,
            next_hop,
            interface: raw.interface,
            metric: raw.metric,
        })
    }
}

impl HornetConfig {
    fn from_raw(raw: RawHornetConfig) -> Result<Self, ConfigError> {
        let listen_addr = parse_ip_addr_any(raw.listen_addr.as_deref().unwrap_or("0.0.0.0"))?;

        let listen_port = raw.listen_port.unwrap_or(30_000);
        if listen_port == 0 {
            return Err(ConfigError::InvalidValue(
                "hornet.listen_port must be greater than 0".into(),
            ));
        }

        let node_secret_path = raw.node_secret_path.map(PathBuf::from);
        let sv_seed_hex = raw
            .sv_seed
            .map(|seed| normalize_hex_with_len(&seed, 16))
            .transpose()?;

        let directory_file = raw.directory_file.map(PathBuf::from);
        let directory_secret_hex = raw
            .directory_secret
            .map(|secret| normalize_hex(&secret))
            .transpose()?;

        let policy_cache_ttl = raw.policy_cache_ttl.unwrap_or(300);
        if policy_cache_ttl == 0 {
            return Err(ConfigError::InvalidValue(
                "hornet.policy_cache_ttl must be greater than 0".into(),
            ));
        }

        let policy_routes = raw
            .policy_routes
            .into_iter()
            .map(HornetPolicyRoute::from_raw)
            .collect::<Result<Vec<_>, _>>()?;

        Ok(HornetConfig {
            enabled: raw.enabled,
            listen_addr,
            listen_port,
            node_secret_path,
            sv_seed_hex,
            directory_file,
            directory_secret_hex,
            policy_cache_ttl,
            policy_routes,
        })
    }
}

impl From<RawNatRole> for NatRole {
    fn from(value: RawNatRole) -> Self {
        match value {
            RawNatRole::Inside => NatRole::Inside,
            RawNatRole::Outside => NatRole::Outside,
        }
    }
}

fn load_raw_config(path: &Path) -> Result<RawRouterConfig, ConfigError> {
    let data = std::fs::read_to_string(path)?;
    let cfg: RawRouterConfig = serde_yaml::from_str(&data)?;
    Ok(cfg)
}

fn parse_ipv4_addr(input: &str) -> Result<Ipv4Addr, ConfigError> {
    input
        .parse::<Ipv4Addr>()
        .map_err(|e| ConfigError::InvalidValue(format!("invalid IPv4 address `{}`: {}", input, e)))
}

fn parse_ipv6_addr(input: &str) -> Result<Ipv6Addr, ConfigError> {
    input
        .parse::<Ipv6Addr>()
        .map_err(|e| ConfigError::InvalidValue(format!("invalid IPv6 address `{}`: {}", input, e)))
}

fn parse_ipv4_network(input: &str) -> Result<Ipv4Network, ConfigError> {
    let (addr_str, prefix_str) = input
        .split_once('/')
        .ok_or_else(|| ConfigError::InvalidValue(format!("CIDR must contain `/`: {}", input)))?;
    let address = parse_ipv4_addr(addr_str.trim())?;
    let prefix = prefix_str.trim().parse::<u8>().map_err(|e| {
        ConfigError::InvalidValue(format!("invalid prefix `{}`: {}", prefix_str, e))
    })?;
    if prefix > 32 {
        return Err(ConfigError::InvalidValue(format!(
            "prefix must be <= 32: {}",
            input
        )));
    }
    Ok(Ipv4Network { address, prefix })
}

fn parse_mac_address(input: &str) -> Result<[u8; 6], ConfigError> {
    let parts: Vec<&str> = input.split(':').collect();
    if parts.len() != 6 {
        return Err(ConfigError::InvalidValue(format!(
            "invalid MAC address `{}`",
            input
        )));
    }
    let mut mac = [0u8; 6];
    for (idx, chunk) in parts.iter().enumerate() {
        mac[idx] = u8::from_str_radix(chunk, 16).map_err(|e| {
            ConfigError::InvalidValue(format!("invalid MAC address `{}`: {}", input, e))
        })?;
    }
    Ok(mac)
}

fn parse_ip_addr_any(input: &str) -> Result<IpAddr, ConfigError> {
    input
        .parse::<IpAddr>()
        .map_err(|e| ConfigError::InvalidValue(format!("invalid IP address `{}`: {}", input, e)))
}

fn normalize_hex(input: &str) -> Result<String, ConfigError> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(ConfigError::InvalidValue(
            "hex string must not be empty".into(),
        ));
    }
    if trimmed.len() % 2 != 0 {
        return Err(ConfigError::InvalidValue(format!(
            "hex string `{}` must have even length",
            trimmed
        )));
    }
    if !trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(ConfigError::InvalidValue(format!(
            "hex string `{}` contains non-hex characters",
            trimmed
        )));
    }
    Ok(trimmed.to_ascii_lowercase())
}

fn normalize_hex_with_len(input: &str, expected_bytes: usize) -> Result<String, ConfigError> {
    let normalized = normalize_hex(input)?;
    if normalized.len() != expected_bytes * 2 {
        return Err(ConfigError::InvalidValue(format!(
            "hex string `{}` must encode {} bytes ({} hex chars)",
            normalized,
            expected_bytes,
            expected_bytes * 2
        )));
    }
    Ok(normalized)
}

fn hex_to_bytes(input: &str) -> Result<Vec<u8>, ConfigError> {
    let normalized = normalize_hex(input)?;
    let mut bytes = Vec::with_capacity(normalized.len() / 2);
    let mut chars = normalized.as_bytes().chunks_exact(2);
    for chunk in &mut chars {
        let hi = chunk[0];
        let lo = chunk[1];
        let value = (hex_digit(hi)? << 4) | hex_digit(lo)?;
        bytes.push(value);
    }
    Ok(bytes)
}

fn hex_encode_bytes(bytes: &[u8]) -> String {
    const TABLE: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(TABLE[(b >> 4) as usize] as char);
        out.push(TABLE[(b & 0x0f) as usize] as char);
    }
    out
}

fn hex_digit(b: u8) -> Result<u8, ConfigError> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(ConfigError::InvalidValue(format!(
            "invalid hex character `{}`",
            b as char
        ))),
    }
}

#[derive(Debug, Deserialize, Default)]
struct RawRouterConfig {
    #[serde(default)]
    mode: Option<String>,
    #[serde(default)]
    debug_level: Option<String>,
    #[serde(default)]
    devices: Vec<RawDeviceConfig>,
    #[serde(default)]
    routes: Vec<RawRouteConfig>,
    #[serde(default)]
    hornet: Option<RawHornetConfig>,
}

#[derive(Debug, Deserialize)]
struct RawDeviceConfig {
    name: String,
    #[serde(default = "default_true")]
    enabled: bool,
    #[serde(default)]
    ignore: bool,
    #[serde(default)]
    mac: Option<String>,
    #[serde(default)]
    ipv4: Vec<String>,
    #[serde(default)]
    mtu: Option<u32>,
    #[serde(default)]
    nat: Option<RawDeviceNatConfig>,
}

#[derive(Debug, Deserialize)]
struct RawDeviceNatConfig {
    role: RawNatRole,
    #[serde(default)]
    outside_ip: Option<String>,
}

#[derive(Debug, Deserialize, Clone, Copy)]
#[serde(rename_all = "snake_case")]
enum RawNatRole {
    Inside,
    Outside,
}

#[derive(Debug, Deserialize)]
struct RawRouteConfig {
    destination: String,
    #[serde(default)]
    next_hop: Option<String>,
    #[serde(default)]
    interface: Option<String>,
    #[serde(default)]
    metric: Option<u32>,
}

#[derive(Debug, Deserialize, Default)]
struct RawHornetConfig {
    #[serde(default)]
    enabled: bool,
    #[serde(default)]
    listen_addr: Option<String>,
    #[serde(default)]
    listen_port: Option<u16>,
    #[serde(default)]
    node_secret_path: Option<String>,
    #[serde(default)]
    sv_seed: Option<String>,
    #[serde(default)]
    directory_file: Option<String>,
    #[serde(default)]
    directory_secret: Option<String>,
    #[serde(default)]
    policy_cache_ttl: Option<u64>,
    #[serde(default)]
    policy_routes: Vec<RawHornetPolicyRoute>,
}

#[derive(Debug, Deserialize, Default)]
struct RawHornetPolicyRoute {
    policy_id: String,
    #[serde(default)]
    interface: Option<String>,
    #[serde(default)]
    segments: Vec<RawRouteElem>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum RawRouteElem {
    NextHop4 {
        ip: String,
        port: u16,
    },
    NextHop6 {
        ip: String,
        port: u16,
    },
    ExitTcp4 {
        ip: String,
        port: u16,
        #[serde(default)]
        tls: bool,
    },
    ExitTcp6 {
        ip: String,
        port: u16,
        #[serde(default)]
        tls: bool,
    },
}

impl HornetPolicyRoute {
    fn from_raw(raw: RawHornetPolicyRoute) -> Result<Self, ConfigError> {
        let policy_bytes = hex_to_bytes(&raw.policy_id)?;
        if policy_bytes.len() != 32 {
            return Err(ConfigError::InvalidValue(format!(
                "hornet.policy_routes policy_id must encode 32 bytes: {}",
                raw.policy_id
            )));
        }
        let mut policy_id = [0u8; 32];
        policy_id.copy_from_slice(&policy_bytes);
        let elems = raw
            .segments
            .into_iter()
            .map(|spec| spec.to_route_elem())
            .collect::<Result<Vec<_>, _>>()?;
        if elems.is_empty() {
            return Err(ConfigError::InvalidValue(
                "hornet.policy_routes entry must contain at least one segment".into(),
            ));
        }
        Ok(HornetPolicyRoute {
            policy_id,
            segment: routing::segment_from_elems(&elems),
            interface: raw.interface,
        })
    }
}

impl RawRouteElem {
    fn to_route_elem(self) -> Result<routing::RouteElem, ConfigError> {
        match self {
            RawRouteElem::NextHop4 { ip, port } => {
                let addr = parse_ipv4_addr(&ip)?;
                Ok(routing::RouteElem::NextHop {
                    addr: routing::IpAddr::V4(addr.octets()),
                    port,
                })
            }
            RawRouteElem::NextHop6 { ip, port } => {
                let addr = parse_ipv6_addr(&ip)?;
                Ok(routing::RouteElem::NextHop {
                    addr: routing::IpAddr::V6(addr.octets()),
                    port,
                })
            }
            RawRouteElem::ExitTcp4 { ip, port, tls } => {
                let addr = parse_ipv4_addr(&ip)?;
                Ok(routing::RouteElem::ExitTcp {
                    addr: routing::IpAddr::V4(addr.octets()),
                    port,
                    tls,
                })
            }
            RawRouteElem::ExitTcp6 { ip, port, tls } => {
                let addr = parse_ipv6_addr(&ip)?;
                Ok(routing::RouteElem::ExitTcp {
                    addr: routing::IpAddr::V6(addr.octets()),
                    port,
                    tls,
                })
            }
        }
    }
}

fn default_true() -> bool {
    true
}
