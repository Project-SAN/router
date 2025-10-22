use crate::ethernet::{format_mac, EthernetHeader};
use crate::net::NetDevice;

const ARP_HTYPE_ETHERNET: u16 = 1;
const ARP_PTYPE_IPV4: u16 = 0x0800;
const ARP_REQUEST: u16 = 1;
const ARP_REPLY: u16 = 2;

#[derive(Debug)]
pub struct ArpPacket {
    pub opcode: u16,
    pub sender_mac: [u8; 6],
    pub sender_ip: [u8; 4],
    pub target_mac: [u8; 6],
    pub target_ip: [u8; 4],
}

impl ArpPacket {
    pub fn parse(payload: &[u8]) -> Option<Self> {
        if payload.len() < 28 {
            return None;
        }
        let htype = u16::from_be_bytes([payload[0], payload[1]]);
        let ptype = u16::from_be_bytes([payload[2], payload[3]]);
        let hlen = payload[4];
        let plen = payload[5];
        let opcode = u16::from_be_bytes([payload[6], payload[7]]);
        if htype != ARP_HTYPE_ETHERNET || ptype != ARP_PTYPE_IPV4 || hlen != 6 || plen != 4 {
            return None;
        }
        let mut sender_mac = [0u8; 6];
        sender_mac.copy_from_slice(&payload[8..14]);
        let mut sender_ip = [0u8; 4];
        sender_ip.copy_from_slice(&payload[14..18]);
        let mut target_mac = [0u8; 6];
        target_mac.copy_from_slice(&payload[18..24]);
        let mut target_ip = [0u8; 4];
        target_ip.copy_from_slice(&payload[24..28]);
        Some(Self {
            opcode,
            sender_mac,
            sender_ip,
            target_mac,
            target_ip,
        })
    }
}

pub fn handle_frame(device: &mut NetDevice, header: &EthernetHeader, payload: &[u8]) {
    let Some(packet) = ArpPacket::parse(payload) else {
        return;
    };

    match packet.opcode {
        ARP_REQUEST => {
            println!(
                "[{}] ARP request {}({}) → {}({})",
                device.name,
                ipv4_to_string(&packet.sender_ip),
                format_mac(&packet.sender_mac),
                ipv4_to_string(&packet.target_ip),
                format_mac(&packet.target_mac),
            );
            println!(
                "    frame {} -> {}",
                format_mac(&header.src),
                format_mac(&header.dest)
            );
        }
        ARP_REPLY => {
            println!(
                "[{}] ARP reply {} is at {}",
                device.name,
                ipv4_to_string(&packet.sender_ip),
                format_mac(&packet.sender_mac)
            );
        }
        _ => {
            println!(
                "[{}] ARP opcode {} from {}",
                device.name,
                packet.opcode,
                format_mac(&packet.sender_mac)
            );
        }
    }
}

fn ipv4_to_string(bytes: &[u8; 4]) -> String {
    format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3])
}
