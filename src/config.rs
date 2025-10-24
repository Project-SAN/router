use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

#[derive(Debug, Clone, Serialize)]
pub struct RouterConfig {
    pub mode: String,
    pub debug_level: String,
    pub config_path: PathBuf,
    pub devices: Vec<DeviceConfig>,
    pub routes: Vec<RouteConfig>,
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

        Ok(Self {
            mode,
            debug_level,
            config_path: path.to_path_buf(),
            devices,
            routes,
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

fn parse_ipv4_network(input: &str) -> Result<Ipv4Network, ConfigError> {
    let (addr_str, prefix_str) = input
        .split_once('/')
        .ok_or_else(|| ConfigError::InvalidValue(format!("CIDR must contain `/`: {}", input)))?;
    let address = parse_ipv4_addr(addr_str.trim())?;
    let prefix = prefix_str
        .trim()
        .parse::<u8>()
        .map_err(|e| ConfigError::InvalidValue(format!("invalid prefix `{}`: {}", prefix_str, e)))?;
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

fn default_true() -> bool {
    true
}
