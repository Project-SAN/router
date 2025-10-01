use std::fmt::Write as _;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NatDirectionType {
    Incoming,
    Outgoing,
}

#[derive(CLone, Copy, Debug, PartialEq, Eq)]
pub enum NatProtocolType {
    Tcp,
    Udp,
    Icmp,
}

pub const NAT_GLOBAL_PORT_MIN: u16 = 20000;
pub const NAT_GLOBAL_PORT_MAX: u16 = 59999;
pub const NAT_GLOBAL_PORT_SIZE: usize = (NAT_GLOBAL_PORT_MAX - NAT_GLOBAL_PORT_MIN + 1) as usize;
pub const NAT_ICMP_ID_SIZE: u16 = 0xFFFF;

#[derive(Clone, Debug, Default)]
pub struct IpHeader {
    pub header_checksum: u16,
    pub src_addr: u32,
    pub dest_addr: u32,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NetDevice {
    pub name: String,
    pub ipdev: IpDevice,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IpDevice {
    pub address: u32,
    pub natdev: NatDevice,
}

//NAT構造体
#[derive(Clone, Debug, Default)]
pub struct NatPacketHeader<'a> {
    pub packet: &'a [u8],
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NatEntry {
    pub global_ip_addr: u32,
    pub local_ip_addr: u32,
    pub global_port: u16,
    pub local_port: u16,
}

//UDP/TCPのNATテーブル
#[derive(Clone, Debug)]
pub struct NatEntryList {
    pub tcp: Vec<Option<NatEntry>>,
    pub udp: Vec<Option<NatEntry>>,
}

impl Default for NatEntryList {
    fn default() -> Self {
        Self {
            tcp: vec![None; NAT_GLOBAL_PORT_SIZE],
            udp: vec![None; NAT_GLOBAL_PORT_SIZE],
        }
    }
}

//NATデバイス
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NatDevice {
    pub outside_ip_addr: u32,
    pub nat_entry: NatEntryList,
}

#[derive(Clone, Debug, Default)]
struct UdpHeader {
    src_port: u16,
    dest_port: u16,
    checksum: u16,
    payload: Vec<u8>,
}
impl UdpHeader {
    fn parse_packet(pkt: &[u8]) -> Self {
        if pkt.len() < 8 {
            return Self::default();
        }
        let src = u16::from_be_bytes([pkt[0], pkt[1]]);
        let dst = u16::from_be_bytes([pkt[2], pkt[3]]);
        let csum = u16::from_be_bytes([pkt[6], pkt[7]]);
        let payload = pkt[8..].to_vec();
        Self { src_port: src, dest_port: dst, checksum: csum, payload }
    }
    fn to_packet(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(8 + self.payload.len());
        b.extend_from_slice(&self.src_port.to_be_bytes());
        b.extend_from_slice(&self.dest_port.to_be_bytes());
        b.extend_from_slice(&((8 + self.payload.len()) as u16).to_be_bytes());
        b.extend_from_slice(&self.checksum.to_be_bytes());
        b.extend_from_slice(&self.payload);
        b
    }
}

#[derive(Clone, Debug, Default)]
struct TcpHeader {
    src_port: u16,
    dest_port: u16,
    checksum: u16,
    rest: Vec<u8>,
}
impl TcpHeader {
    fn parse_packet(pkt: &[u8]) -> Self {
        if pkt.len() < 20 {
            return Self::default();
        }
        let src = u16::from_be_bytes([pkt[0], pkt[1]]);
        let dst = u16::from_be_bytes([pkt[2], pkt[3]]);
        let data_off = ((pkt[12] >> 4) as usize) * 4;
        let csum  u16::from_be_bytes([pkt[16], pkt[17]]);
        let rest = pkt[20..].to_vec();

        let mut h = Self { src_port: src, dest_port: dst, checksum: csum, rest };
        if data_off > 20 && data_off <= pkt.len() {
            h.rest = pkt[data_off..].to_vec();
        }
        h
    }
    fn to_packet(&self) -> Vec<u8> {
        let mut b = vec![0u8; 20];
        b[0..2].copy_from_slice(&self.src_port.to_be_bytes());
        b[2..4].copy_from_slice(&self.dest_port.to_be_bytes());
        b[12] = 5 << 4;
        b[16..18].copy_from_slice(&self.checksum.to_be_bytes());
        b.extend_from_slice(&self.rest);
        b
    }
}

