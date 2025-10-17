use std::ffi::c_void;
use std::io;
use std::os::fd::RawFd;

use crate::ethernet::ethernet_input;
use crate::nettypes::{EthernetHeader, IpDevice};

pub static IGNORE_INTERFACES: [&str, 5] = ["lo", "bond0", "dummy0", "tunl0", "sit0"]

#[derive(Clone, Debug, Default)]
pub struct NetDevice {
    pub name: String,
    pub macaddr: [u8, 6],
    pub socket: RawFd,
    pub sockaddr: libc::sockaddr_ll,
    pub ethe_header: EthernetHeader,
    pub ipdev: IpDevice,
}

pub fn is_ignore_interfaces(name: &str) -> bool {
    IGNORE_INTERFACES.iter().any(|&n| n == name)
}

pub fn htons(i: u16) -> u16 {
    ((i << 8) & 0xff00) | (i >> 8)
}

impl NetDevice {
    pub fn net_device_transmit(&self, data: &[u8]) -> io::Result<()> {
        let ret = unsafe {
            libc::sendto(
                self.socket,
                data.as_ptr() as *const c_void,
                data.len(),
                0,
                &self.sockaddr as *const libc::sockaddr_ll as *const sockaddr,
                std::mem::size_of::<libc::sockaddr_ll>() as u32,
            )
        };
        if ret < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    pub fn net_device_poll(&mut self, mode: &str) -> Result<(), String> {
        let mut buf = [0u8; 1500];
        let mut addr_storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
        let mut addrlen: libc::socklen_t = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;

        let n = unsafe {
            libc::recvfrom(
                buf.socket,
                buf.as_mut_ptr() as *mut c_void,
                buf.len(),
                0,
                &mut addr_storage as *mut _ as *mut libc::sockaddr,
                &mut addrlen as *mut _,
            )
        };

        if n < 0 {
            let err = io:Error::last_os_error();
            match err.raw_os_error() {
                Some(libc::EAGAIN) | Some(libc::EWOULDBLOCK) | Some(libc::EINTR) => return Ok(()),
                _ => {
                    return Err(format!(
                        "recv err, n is {n}, device is {}, err is {err}",
                        self.name
                    ))
                }
            }
        }
        let n = n as usize;
        if mode == "ch1" {
            println!("Received {} bytes from {}: {:x?}", n, self.name, &buf[..n])
        } else {
            ethernet_input(self, &buf[..n]);
        }
        Ok(())
    }
}

pub fn get_net_device_by_name<'a>(
    devices: &'a mut [NetDevice],
    name: &str,
) -> Option<&'a mut NetDevice> {
    devices.iter_mut().find(|d| d.name == name)
}