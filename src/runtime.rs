use crate::config::{DeviceConfig, NatRole, RouteConfig, RouterConfig};
use crate::ethernet::ethernet_input;
use crate::ip::{
    self, EthernetHeader as IpEthernetHeader, IpDevice as IpIpDevice, IpRouteEntry, IpRouteType,
    NatDevice as IpNatDevice, NetDevice as IpNetDevice, RouteEntryConfig as IpRouteEntryConfig,
};
use std::collections::HashMap;
use std::ffi::CString;
use std::fmt;
use std::io;
use std::mem;
use std::net::Ipv4Addr;
use std::os::fd::RawFd;
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;
use std::time::Duration;

#[derive(Debug)]
pub enum InitError {
    MissingPrimaryAddress(String),
    InvalidNetmaskPrefix { device: String, prefix: u8 },
    MissingOutsideNatPeer(String),
    RouteBuild(String),
    SocketInit { device: String, source: io::Error },
    DeviceRegistry(String),
    IpModule(String),
}

impl fmt::Display for InitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InitError::MissingPrimaryAddress(dev) => {
                write!(f, "device `{}` has no IPv4 address", dev)
            }
            InitError::InvalidNetmaskPrefix { device, prefix } => {
                write!(
                    f,
                    "device `{}` has invalid prefix length `{}`",
                    device, prefix
                )
            }
            InitError::MissingOutsideNatPeer(dev) => write!(
                f,
                "device `{}` is configured for NAT inside but no outside peer is defined",
                dev
            ),
            InitError::RouteBuild(msg) => write!(f, "route configuration error: {}", msg),
            InitError::SocketInit { device, source } => {
                write!(
                    f,
                    "failed to initialise raw socket for `{}`: {}",
                    device, source
                )
            }
            InitError::DeviceRegistry(msg) => write!(f, "device registry error: {}", msg),
            InitError::IpModule(err) => write!(f, "failed to update IP module devices: {}", err),
        }
    }
}

impl std::error::Error for InitError {}

pub fn initialize_network_state(cfg: &RouterConfig) -> Result<(), InitError> {
    let active_devices: Vec<&DeviceConfig> = cfg
        .devices
        .iter()
        .filter(|dev| dev.enabled && !dev.ignore)
        .collect();

    let outside_ip_map = collect_outside_nat_ips(&active_devices)?;
    let ip_devices = build_ip_devices(&active_devices, &outside_ip_map)?;
    let ip_devices_clone = ip_devices.clone();

    ip::set_net_devices(ip_devices).map_err(InitError::IpModule)?;

    let device_index: HashMap<_, _> = ip_devices_clone
        .into_iter()
        .map(|dev| (dev.name.clone(), dev))
        .collect();

    let route_entries = build_route_entries(&cfg.routes, &device_index)?;
    ip::set_route_entries(route_entries).map_err(InitError::IpModule)?;

    let raw_devices = initialise_raw_devices(&device_index)?;
    register_runtime_devices(raw_devices)?;
    Ok(())
}

fn collect_outside_nat_ips(
    devices: &[&DeviceConfig],
) -> Result<HashMap<String, Ipv4Addr>, InitError> {
    let mut map = HashMap::new();
    for dev in devices {
        if let Some(nat) = &dev.nat {
            if nat.role == NatRole::Outside {
                let primary = dev
                    .ipv4
                    .first()
                    .ok_or_else(|| InitError::MissingPrimaryAddress(dev.name.clone()))?;
                let outside_ip = nat.outside_ip.unwrap_or(primary.address);
                map.insert(dev.name.clone(), outside_ip);
            }
        }
    }
    Ok(map)
}

fn build_ip_devices(
    devices: &[&DeviceConfig],
    outside_ip_map: &HashMap<String, Ipv4Addr>,
) -> Result<Vec<IpNetDevice>, InitError> {
    let mut result = Vec::with_capacity(devices.len());
    let fallback_outside_ip = outside_ip_map.values().next().copied();
    let mut nat_states: HashMap<u32, Arc<Mutex<crate::nat::NatDevice>>> = HashMap::new();

    for dev in devices {
        let primary = dev
            .ipv4
            .first()
            .ok_or_else(|| InitError::MissingPrimaryAddress(dev.name.clone()))?;

        let mask =
            prefix_to_netmask(primary.prefix).ok_or_else(|| InitError::InvalidNetmaskPrefix {
                device: dev.name.clone(),
                prefix: primary.prefix,
            })?;
        let address = u32::from(primary.address);
        let broadcast = address | (!mask);

        let mac = dev.mac.unwrap_or([0u8; 6]);

        let mut ipdev = IpIpDevice {
            address,
            netmask: mask,
            broadcast,
            natdev: IpNatDevice::default(),
        };

        if let Some(nat_cfg) = &dev.nat {
            let outside_ip = match nat_cfg.role {
                NatRole::Outside => nat_cfg.outside_ip.unwrap_or(primary.address),
                NatRole::Inside => nat_cfg
                    .outside_ip
                    .or(fallback_outside_ip)
                    .ok_or_else(|| InitError::MissingOutsideNatPeer(dev.name.clone()))?,
            };
            let outside_ip_u32 = u32::from(outside_ip);
            let state = nat_states
                .entry(outside_ip_u32)
                .or_insert_with(|| {
                    let mut nat_dev = crate::nat::NatDevice::default();
                    nat_dev.outside_ip_addr = outside_ip_u32;
                    Arc::new(Mutex::new(nat_dev))
                })
                .clone();

            ipdev.natdev = match nat_cfg.role {
                NatRole::Outside => IpNatDevice::for_outside(outside_ip_u32, state),
                NatRole::Inside => IpNatDevice::for_inside(outside_ip_u32, state),
            };
        }

        let mut ethernet_header = IpEthernetHeader::default();
        ethernet_header.src_addr = mac;

        result.push(IpNetDevice {
            name: dev.name.clone(),
            ipdev,
            ethe_header: ethernet_header,
            macaddr: mac,
        });
    }

    Ok(result)
}

fn build_route_entries(
    routes: &[RouteConfig],
    device_index: &HashMap<String, IpNetDevice>,
) -> Result<Vec<IpRouteEntryConfig>, InitError> {
    let mut result = Vec::with_capacity(routes.len());

    for route in routes {
        let interface_name = route.interface.as_ref().ok_or_else(|| {
            InitError::RouteBuild(format!(
                "route to {}/{} requires `interface`",
                route.destination.address, route.destination.prefix
            ))
        })?;

        let Some(dev) = device_index.get(interface_name) else {
            eprintln!(
                "warning: skipping route {}/{} because interface `{}` is not initialised",
                route.destination.address, route.destination.prefix, interface_name
            );
            continue;
        };

        let entry = if let Some(next_hop) = route.next_hop {
            IpRouteEntry {
                iptype: IpRouteType::Network,
                netdev: dev.clone(),
                nexthop: u32::from(next_hop),
            }
        } else {
            IpRouteEntry {
                iptype: IpRouteType::Connected,
                netdev: dev.clone(),
                nexthop: 0,
            }
        };

        let Some(netmask) = prefix_to_netmask(route.destination.prefix) else {
            return Err(InitError::RouteBuild(format!(
                "invalid prefix length {} for {}",
                route.destination.prefix, route.destination.address
            )));
        };
        let network = u32::from(route.destination.address) & netmask;

        result.push(IpRouteEntryConfig {
            prefix: network,
            prefix_len: route.destination.prefix,
            entry,
        });
    }

    Ok(result)
}

fn prefix_to_netmask(prefix: u8) -> Option<u32> {
    if prefix > 32 {
        return None;
    }
    if prefix == 0 {
        return Some(0);
    }
    let mask = (!0u32).checked_shl(32 - prefix as u32)?;
    Some(mask)
}

#[derive(Debug)]
struct RawSocketDevice {
    socket: RawFd,
    sockaddr: libc::sockaddr_ll,
    iface: IpNetDevice,
}

impl Drop for RawSocketDevice {
    fn drop(&mut self) {
        if self.socket >= 0 {
            unsafe {
                libc::close(self.socket);
            }
        }
    }
}

impl RawSocketDevice {
    fn name(&self) -> &str {
        &self.iface.name
    }
}

static RUNTIME_DEVICES: OnceLock<Mutex<Vec<RawSocketDevice>>> = OnceLock::new();

fn device_store() -> &'static Mutex<Vec<RawSocketDevice>> {
    RUNTIME_DEVICES.get_or_init(|| Mutex::new(Vec::new()))
}

fn initialise_raw_devices(
    device_index: &HashMap<String, IpNetDevice>,
) -> Result<Vec<RawSocketDevice>, InitError> {
    let mut result = Vec::with_capacity(device_index.len());
    for iface in device_index.values() {
        match open_raw_socket(iface) {
            Ok(dev) => result.push(dev),
            Err(InitError::SocketInit { device, source })
                if source.kind() == io::ErrorKind::PermissionDenied =>
            {
                eprintln!(
                    "warning: insufficient permissions to open raw socket on `{}`: {}",
                    device, source
                );
            }
            Err(e) => return Err(e),
        }
    }
    Ok(result)
}

fn open_raw_socket(iface: &IpNetDevice) -> Result<RawSocketDevice, InitError> {
    const ETH_P_ALL: u16 = 0x0003;

    let fd = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_RAW, htons(ETH_P_ALL) as i32) };
    if fd < 0 {
        return Err(InitError::SocketInit {
            device: iface.name.clone(),
            source: io::Error::last_os_error(),
        });
    }

    let c_name = CString::new(iface.name.clone()).map_err(|_| InitError::SocketInit {
        device: iface.name.clone(),
        source: io::Error::new(
            io::ErrorKind::InvalidInput,
            "interface name contains null byte",
        ),
    })?;

    let if_index = unsafe { libc::if_nametoindex(c_name.as_ptr()) };
    if if_index == 0 {
        let err = io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(InitError::SocketInit {
            device: iface.name.clone(),
            source: err,
        });
    }

    let mut sockaddr: libc::sockaddr_ll = unsafe { mem::zeroed() };
    sockaddr.sll_family = libc::AF_PACKET as libc::c_ushort;
    sockaddr.sll_protocol = htons(ETH_P_ALL);
    sockaddr.sll_ifindex = if_index as libc::c_int;
    sockaddr.sll_halen = iface.macaddr.len() as u8;
    for (idx, byte) in iface.macaddr.iter().enumerate() {
        if idx < sockaddr.sll_addr.len() {
            sockaddr.sll_addr[idx] = *byte;
        }
    }

    let bind_res = unsafe {
        libc::bind(
            fd,
            &sockaddr as *const libc::sockaddr_ll as *const libc::sockaddr,
            mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
        )
    };
    if bind_res < 0 {
        let err = io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(InitError::SocketInit {
            device: iface.name.clone(),
            source: err,
        });
    }

    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL);
        if flags >= 0 {
            libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
        }
    }

    Ok(RawSocketDevice {
        socket: fd,
        sockaddr,
        iface: iface.clone(),
    })
}

fn register_runtime_devices(devices: Vec<RawSocketDevice>) -> Result<(), InitError> {
    let store = device_store();
    let mut guard = store
        .lock()
        .map_err(|_| InitError::DeviceRegistry("runtime device store is poisoned".to_string()))?;
    *guard = devices;
    Ok(())
}

fn htons(i: u16) -> u16 {
    i.to_be()
}

pub fn runtime_device_descriptors() -> Result<Vec<(String, RawFd)>, String> {
    let guard = device_store()
        .lock()
        .map_err(|_| "runtime device store is poisoned".to_string())?;
    Ok(guard
        .iter()
        .map(|dev| (dev.name().to_string(), dev.socket))
        .collect())
}

pub fn has_runtime_devices() -> bool {
    device_store()
        .lock()
        .map(|g| g.iter().any(|dev| dev.socket >= 0))
        .unwrap_or(false)
}

pub fn transmit_frame(interface: &str, dest_mac: [u8; 6], frame: &[u8]) -> Result<(), String> {
    let guard = device_store()
        .lock()
        .map_err(|_| "runtime device store is poisoned".to_string())?;

    let dev = guard
        .iter()
        .find(|d| d.socket >= 0 && d.name() == interface)
        .ok_or_else(|| format!("interface `{}` is not initialised", interface))?;

    let mut sockaddr = dev.sockaddr;
    for (idx, byte) in dest_mac.iter().enumerate() {
        if idx < sockaddr.sll_addr.len() {
            sockaddr.sll_addr[idx] = *byte;
        }
    }

    let ret = unsafe {
        libc::sendto(
            dev.socket,
            frame.as_ptr() as *const libc::c_void,
            frame.len(),
            0,
            &sockaddr as *const libc::sockaddr_ll as *const libc::sockaddr,
            mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
        )
    };
    if ret < 0 {
        Err(format!(
            "sendto failed on {}: {}",
            interface,
            io::Error::last_os_error()
        ))
    } else {
        Ok(())
    }
}

pub fn run_event_loop(mode: &str) -> Result<(), String> {
    if !has_runtime_devices() {
        println!("no raw sockets initialised; event loop not started");
        return Ok(());
    }

    loop {
        let processed = poll_devices(mode)?;
        if !processed {
            thread::sleep(Duration::from_millis(10));
        }
    }
}

fn poll_devices(mode: &str) -> Result<bool, String> {
    let mut processed = false;
    {
        let mut guard = device_store()
            .lock()
            .map_err(|_| "runtime device store is poisoned".to_string())?;
        for dev in guard.iter_mut() {
            processed |= recv_from_device(dev, mode)?;
        }
    }
    Ok(processed)
}

fn recv_from_device(dev: &mut RawSocketDevice, mode: &str) -> Result<bool, String> {
    let mut handled = false;
    let mut buf = [0u8; 2048];
    loop {
        let n = unsafe {
            libc::recv(
                dev.socket,
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
                0,
            )
        };
        if n < 0 {
            let err = io::Error::last_os_error();
            match err.kind() {
                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted => break,
                _ => match err.raw_os_error() {
                    Some(code) if code == libc::ENETDOWN || code == libc::ENETRESET => {
                        eprintln!("warning: interface {} is down: {}", dev.name(), err);
                        break;
                    }
                    _ => return Err(format!("recv error on {}: {}", dev.name(), err)),
                },
            }
        } else if n == 0 {
            break;
        } else {
            handled = true;
            let n = n as usize;
            if mode == "ch1" {
                println!(
                    "Received {} bytes from {}: {:02x?}",
                    n,
                    dev.name(),
                    &buf[..n]
                );
            } else {
                ethernet_input(&mut dev.iface, &buf[..n]);
            }
        }
    }
    Ok(handled)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{DeviceNatConfig, Ipv4Network};
    use std::net::Ipv4Addr;

    fn mk_device(
        name: &str,
        addr: (u8, u8, u8, u8),
        prefix: u8,
        nat: Option<DeviceNatConfig>,
    ) -> DeviceConfig {
        DeviceConfig {
            name: name.to_string(),
            enabled: true,
            ignore: false,
            mac: Some([0, 1, 2, 3, 4, 5]),
            ipv4: vec![Ipv4Network {
                address: Ipv4Addr::new(addr.0, addr.1, addr.2, addr.3),
                prefix,
            }],
            mtu: None,
            nat,
        }
    }

    #[test]
    fn inside_nat_uses_outside_peer_when_not_specified() {
        let outside_nat = DeviceNatConfig {
            role: NatRole::Outside,
            outside_ip: Some(Ipv4Addr::new(203, 0, 113, 2)),
        };
        let inside_nat = DeviceNatConfig {
            role: NatRole::Inside,
            outside_ip: None,
        };

        let configs = vec![
            mk_device("wan", (203, 0, 113, 2), 30, Some(outside_nat)),
            mk_device("lan", (192, 168, 10, 1), 24, Some(inside_nat)),
        ];
        let device_refs: Vec<&DeviceConfig> = configs.iter().collect();

        let outside_map = super::collect_outside_nat_ips(&device_refs).unwrap();
        let ip_devices = super::build_ip_devices(&device_refs, &outside_map).unwrap();

        let lan_dev = ip_devices
            .iter()
            .find(|d| d.name == "lan")
            .expect("lan device created");
        assert_eq!(
            lan_dev.ipdev.natdev.outside_ip_addr,
            u32::from(Ipv4Addr::new(203, 0, 113, 2))
        );
        assert!(lan_dev.ipdev.natdev.shared_state().is_some());
    }
}
