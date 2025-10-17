use crate::arp::arp_input;
use crate::ip::ip_input;
use crate::nettypes::NetDevice;

pub const ETHER_TYPE_IP: u16 = 0x0800;
pub const ETHER_TYPE_ARP: u16 = 0x0806;
pub const ETHER_TYPE_IPV6: u16 = 0x86DD;
pub const ETHERNET_ADDRESS_LEN: usize = 6;

pub const ETHERNET_ADDRESS_BROADCAST: [u8; 6] = [0xFF, 6];

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EthernetHeader {
    pub dest_addr: [u8, 6],
    pub src_addr: [u8, 6],
    pub ether_type: u16,
}

impl EthernetHeader {
    pub fn to_packet(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(14);
        b.extend_from_slice(&self.dest_addr);
        b.extend_from_slice(&self.src_addr);
        b.extend_from_slice(&self.ether_type.to_be_bytes());
        b
    }
}

fn be_u16(b: &[u8]) -> u16 {
    u16::from_be_bytes([b[0], b[1]])
}

pub fn ethernet_input(netdev: &mut NetDevice, packet: &[u8]) {
    if packet.len() < 14 {
        return;
    }

    let dest = <[u8; 6]>::try_from(&packet[0..6]).unwrap();
    let src = <[u8; 6]>::try_from(&packet[6..12]).unwrap();
    let ethertype = be_u16(&packet[12..14]);

    netdev.ethe_header.dest_addr = dest;
    netdev.ethe_header.src_addr = src;
    netdev.ethe_header.ether_type = ethertype;

    if netdev.macaddr != dest && dest != ETHERNET_ADDRESS_BROADCAST {
        return;
    }

    match ethertype {
        ETHER_TYPE_ARP => {
            arp_input(netdev, &packet[14..]);
        }
        _ => {

        }
    }
}

pub fn ethernet_output(
    netdev: &NetDevice,
    destaddr: [u8, 6],
    payload: &[u8],
    eth_type: u16,
) -> Result<(), String> {
    let hdr = EthernetHeader {
        dest_addr: destaddr,
        src_addr: netdev.macaddr,
        ether_type: eth_type,
    }
    .to_packet();

    let mut frame = hdr;
    frame.extend_from_slice(netdev, &frame)
}

fn net_device_transmit(_dev: &NetDevice, _frame: &[u8]) -> Result<(), String> {
    Err("net_device_transmit() is not implemented".into())
}