use crate::arp;
use crate::net::NetDevice;

pub const ETHER_TYPE_ARP: u16 = 0x0806;
pub const ETHER_TYPE_IP: u16 = 0x0800;

#[derive(Clone, Debug)]
pub struct EthernetHeader {
    pub dest: [u8; 6],
    pub src: [u8; 6],
    pub ether_type: u16,
}

impl EthernetHeader {
    pub fn parse(frame: &[u8]) -> Option<Self> {
        if frame.len() < 14 {
            return None;
        }
        let mut dest = [0u8; 6];
        dest.copy_from_slice(&frame[0..6]);
        let mut src = [0u8; 6];
        src.copy_from_slice(&frame[6..12]);
        let ether_type = u16::from_be_bytes([frame[12], frame[13]]);
        Some(Self {
            dest,
            src,
            ether_type,
        })
    }
}

pub fn process_frame(device: &mut NetDevice, frame: &[u8]) {
    let Some(header) = EthernetHeader::parse(frame) else {
        return;
    };
    let payload = &frame[14..];

    match header.ether_type {
        ETHER_TYPE_ARP => arp::handle_frame(device, &header, payload),
        ETHER_TYPE_IP => {
            println!(
                "[{}] IPv4 frame {} -> {} ({} bytes)",
                device.name,
                format_mac(&header.src),
                format_mac(&header.dest),
                payload.len()
            );
        }
        _ => {
            println!(
                "[{}] ether_type 0x{:04x} {} -> {} ({} bytes)",
                device.name,
                header.ether_type,
                format_mac(&header.src),
                format_mac(&header.dest),
                payload.len()
            );
        }
    }
}

pub fn format_mac(mac: &[u8; 6]) -> String {
    static HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(17);
    for (i, b) in mac.iter().enumerate() {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
        if i != 5 {
            out.push(':');
        }
    }
    out
}
