use std::collections::BTreeMap;
use std::ffi::{CStr, CString};
use std::io;
use std::mem;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::fd::RawFd;

pub const ETH_P_ALL: u16 = 0x0003;

pub struct NetDevice {
    pub name: String,
    pub mac: [u8; 6],
    fd: RawFd,
    sockaddr: libc::sockaddr_ll,
}

impl NetDevice {
    pub fn open(name: &str) -> io::Result<Self> {
        let fd = unsafe {
            libc::socket(
                libc::AF_PACKET,
                libc::SOCK_RAW | libc::SOCK_NONBLOCK,
                htons(ETH_P_ALL) as i32,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }

        let if_name = CString::new(name)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "iface name"))?;
        let index = unsafe { libc::if_nametoindex(if_name.as_ptr()) };
        if index == 0 {
            unsafe { libc::close(fd) };
            return Err(io::Error::last_os_error());
        }

        let mut mac = [0u8; 6];
        fetch_mac(fd, &if_name, &mut mac)?;

        let mut sockaddr: libc::sockaddr_ll = unsafe { mem::zeroed() };
        sockaddr.sll_family = libc::AF_PACKET as u16;
        sockaddr.sll_protocol = htons(ETH_P_ALL);
        sockaddr.sll_ifindex = index as i32;
        sockaddr.sll_halen = mac.len() as u8;
        sockaddr.sll_addr[..mac.len()].copy_from_slice(&mac);

        let bind_res = unsafe {
            libc::bind(
                fd,
                &sockaddr as *const libc::sockaddr_ll as *const libc::sockaddr,
                mem::size_of::<libc::sockaddr_ll>() as u32,
            )
        };
        if bind_res < 0 {
            unsafe { libc::close(fd) };
            return Err(io::Error::last_os_error());
        }

        Ok(Self {
            name: name.to_owned(),
            mac,
            fd,
            sockaddr,
        })
    }

    pub fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let res =
            unsafe { libc::recv(self.fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
        if res < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::WouldBlock {
                return Ok(0);
            }
            return Err(err);
        }
        Ok(res as usize)
    }

    pub fn send(&self, frame: &[u8]) -> io::Result<usize> {
        let res = unsafe {
            libc::sendto(
                self.fd,
                frame.as_ptr() as *const libc::c_void,
                frame.len(),
                0,
                &self.sockaddr as *const libc::sockaddr_ll as *const libc::sockaddr,
                mem::size_of::<libc::sockaddr_ll>() as u32,
            )
        };
        if res < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(res as usize)
    }
}

impl Drop for NetDevice {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd) };
    }
}

pub struct InterfaceInfo {
    pub name: String,
    pub addresses: Vec<String>,
    pub mac: Option<[u8; 6]>,
}

pub fn list_interfaces() -> io::Result<Vec<InterfaceInfo>> {
    unsafe {
        let mut ifaddrs: *mut libc::ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(&mut ifaddrs) != 0 {
            return Err(io::Error::last_os_error());
        }
        let mut map: BTreeMap<String, InterfaceInfo> = BTreeMap::new();
        let mut cursor = ifaddrs;
        while !cursor.is_null() {
            let iface = &*cursor;
            let name = if iface.ifa_name.is_null() {
                "<unknown>".to_string()
            } else {
                CStr::from_ptr(iface.ifa_name)
                    .to_string_lossy()
                    .into_owned()
            };
            let entry = map.entry(name.clone()).or_insert_with(|| InterfaceInfo {
                name: name.clone(),
                addresses: Vec::new(),
                mac: fetch_mac_from_name(iface.ifa_name).ok(),
            });
            if let Some(addr) = sockaddr_to_string(iface.ifa_addr) {
                if !entry.addresses.contains(&addr) {
                    entry.addresses.push(addr);
                }
            }
            cursor = iface.ifa_next;
        }
        libc::freeifaddrs(ifaddrs);
        Ok(map.into_values().collect())
    }
}

fn fetch_mac(fd: RawFd, name: &CString, mac_out: &mut [u8; 6]) -> io::Result<()> {
    let mut ifr: libc::ifreq = unsafe { mem::zeroed() };
    copy_name(&mut ifr.ifr_name, name)?;
    let res = unsafe { libc::ioctl(fd, libc::SIOCGIFHWADDR, &mut ifr) };
    if res < 0 {
        return Err(io::Error::last_os_error());
    }
    let hwaddr = unsafe { ifr.ifr_ifru.ifru_hwaddr.sa_data };
    for (dst, src) in mac_out.iter_mut().zip(hwaddr.iter()) {
        *dst = *src as u8;
    }
    Ok(())
}

fn fetch_mac_from_name(name: *const libc::c_char) -> io::Result<[u8; 6]> {
    if name.is_null() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "null name"));
    }
    let fd = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_DGRAM, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut ifr: libc::ifreq = unsafe { mem::zeroed() };
    unsafe {
        libc::strncpy(ifr.ifr_name.as_mut_ptr(), name, ifr.ifr_name.len() - 1);
        ifr.ifr_name[ifr.ifr_name.len() - 1] = 0;
    }
    let res = unsafe { libc::ioctl(fd, libc::SIOCGIFHWADDR, &mut ifr) };
    unsafe { libc::close(fd) };
    if res < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut mac = [0u8; 6];
    let hwaddr = unsafe { ifr.ifr_ifru.ifru_hwaddr.sa_data };
    for (dst, src) in mac.iter_mut().zip(hwaddr.iter()) {
        *dst = *src as u8;
    }
    Ok(mac)
}

fn sockaddr_to_string(addr: *const libc::sockaddr) -> Option<String> {
    if addr.is_null() {
        return None;
    }
    unsafe {
        match (*addr).sa_family as libc::c_int {
            libc::AF_INET => {
                let sin = &*(addr as *const libc::sockaddr_in);
                Some(Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr)).to_string())
            }
            libc::AF_INET6 => {
                let sin6 = &*(addr as *const libc::sockaddr_in6);
                Some(Ipv6Addr::from(sin6.sin6_addr.s6_addr).to_string())
            }
            _ => None,
        }
    }
}

fn copy_name(dst: &mut [libc::c_char], name: &CString) -> io::Result<()> {
    let bytes = name.as_bytes_with_nul();
    if bytes.len() > dst.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "interface name too long",
        ));
    }
    for (slot, byte) in dst.iter_mut().zip(bytes.iter()) {
        *slot = *byte as libc::c_char;
    }
    Ok(())
}

fn htons(v: u16) -> u16 {
    v.to_be()
}
