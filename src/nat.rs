use std::fmt::Write as _;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NatDirectionType {
    Incoming,
    Outgoing,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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
#[derive(Clone, Debug, Eq, PartialEq)]
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
        let csum = u16::from_be_bytes([pkt[16], pkt[17]]);
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

fn print_ip_addr(ip: u32) -> String {
    let b = ip.to_be_bytes();
    format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3])
}

fn hex(data: &[u8]) -> String {
    let mut s = String::new();
    for b in data {
        let _ = write!(&mut s, "{:02x}", b);
    }
    s
}

impl NatEntryList {
    pub fn get_nat_entry_by_global(&self, proto: NatProtocolType, ipaddr: u32, port: u16) -> Option<NatEntry> {
        match proto {
            NatProtocolType::Udp => self.udp.iter().filter_map(|e| e.as_ref()).find(|v| v.global_ip_addr == ipaddr && v.global_port == port).cloned(),
            NatProtocolType::Tcp => self.tcp.iter().filter_map(|e| e.as_ref()).find(|v| v.global_ip_addr == ipaddr && v.global_port == port).cloned(),
            NatProtocolType::Icmp => None,
        }
    }

    pub fn get_nat_entry_by_local(&self, proto: NatProtocolType, ipaddr: u32, port: u16) -> Option<NatEntry> {
        match proto {
            NatProtocolType::Udp => self.udp.iter().filter_map(|e| e.as_ref()).find(|v| v.local_ip_addr == ipaddr && v.local_port == port).cloned(),
            NatProtocolType::Tcp => self.tcp.iter().filter_map(|e| e.as_ref()).find(|v| v.local_ip_addr == ipaddr && v.local_port == port).cloned(),
            NatProtocolType::Icmp => None,
        }
    }

    pub fn crate_nat_entry(&mut self, proto: NatProtocolType) -> Option<&mut NatEntry> {
        match proto {
            NatProtocolType::Udp => {
                for (i, slot) in self.udp.iter_mut().enumerate() {
                    if slot.is_none() {
                        *slot = Some(NatEntry { global_port: NAT_GLOBAL_PORT_MIN + i as u16, ..Default::default() });
                        return slot.as_mut();
                    }
                }
            }
            atProtocolType::Tcp => {
                for (i, slot) in self.tcp.iter_mut().enumerate() {
                    if slot.is_none() {
                        *slot = Some(NatEntry { global_port: NAT_GLOBAL_PORT_MIN + i as u16, ..Default::default() });
                        return slot.as_mut();
                    }
                }
            }
            NatProtocolType::Icmp => {}
        }
        None
    }
    fn replace_entry(&mut self, proto: NatProtocolType, old: &NatEntry, new_ent: NatEntry) {
        let vec_ref: &mut Vec<Option<NatEntry>> = match proto {
            NatProtocolType::Udp => &mut self.udp,
            NatProtocolType::Tcp => &mut self.tcp,
            NatProtocolType::Icmp => return,
        };
        for slot in vec_ref.iter_mut() {
            if let Some(e) = slot {
                if e.global_port == old.global_port && e.global_ip_addr == old.global_ip_addr {
                    *e = new_ent;
                    break;
                }
            }
        }
    }
}

pub fn configure_ip_nat(devices: &mut [NetDevice], inside_name: &str, outside_ip: u32) {
    for dev in devices.iter_mut() {
        if dev.name == inside_name {
            dev.ipdev.natdev = NatDevice {
                outside_ip_addr: outside_ip,
                nat_entry: NatEntryList::default(),
            };
            println!("Set nat to {}, outside ip addr is {}", inside_name, print_ip_addr(outside_ip));
        }
    }
}

pub fn dump_nat_tables(devices: &[NetDevice]) {
    println!("|-PROTO-|---------LOCAL---------|--------GLOBAL---------|");
    for netdev in devices.iter() {
        let nat = &netdev.ipdev.natdev;
        if *nat != NatDevice::default() {
            for i in 0..NAT_GLOBAL_PORT_SIZE {
                if let Some(e) = &nat.nat_entry.tcp[i] {
                    if e.global_port != 0 {
                        println!(
                            "|  TCP  | {:>15}:{:05} | {:>15}:{:05} |",
                            e.local_ip_addr, e.local_port, e.global_ip_addr, e.global_port
                        );
                    }
                }
                if let Some(e) = &nat.nat_entry.udp[i] {
                    if e.global_port != 0 {
                        println!(
                            "|  UDP  | {:>15}:{:05} | {:>15}:{:05} |",
                            e.local_ip_addr, e.local_port, e.global_ip_addr, e.global_port
                        );
                    }
                }
            }
        }
    }
    println!("|-------|-----------------------|-----------------------|");
}


pub fn nat_exec(
    ipheader: &mut IpHeader,
    nat_packet: NatPacketHeader<'_>,
    natdevice: &mut NatDevice,
    proto: NatProtocolType,
    direction: NatDirectionType,
) -> Result<Vec<u8>, String> {
    // ICMP NAT は未対応
    if matches!(proto, NatProtocolType::Icmp) {
        return Err("ICMP の NAT は未対応です...".to_string());
    }

    // UDP/TCP をパース
    let (mut udpheader, mut tcpheader);
    let (mut src_port, mut dest_port);
    match proto {
        NatProtocolType::Udp => {
            udpheader = UdpHeader::parse_packet(nat_packet.packet);
            src_port = udpheader.src_port;
            dest_port = udpheader.dest_port;
        }
        NatProtocolType::Tcp => {
            tcpheader = TcpHeader::parse_packet(nat_packet.packet);
            src_port = tcpheader.src_port;
            dest_port = tcpheader.dest_port;
        }
        NatProtocolType::Icmp => unreachable!(),
    }

    // エントリ参照/作成
    match direction {
        NatDirectionType::Incoming => {
            // 外→内：グローバル (dstIP, dstPort) で引く
            let entry_opt = natdevice
                .nat_entry
                .get_nat_entry_by_global(proto, ipheader.dest_addr, dest_port);
            let entry = if let Some(e) = entry_opt {
                e
            } else {
                return Err("No nat entry".into());
            };

            println!(
                "incoming nat from {}:{} to {}:{}",
                print_ip_addr(entry.global_ip_addr),
                entry.global_port,
                print_ip_addr(entry.local_ip_addr),
                entry.local_port
            );
            println!(
                "incoming ip header src is {}, dest is {}",
                print_ip_addr(ipheader.src_addr),
                print_ip_addr(ipheader.dest_addr)
            );

            // IP 宛先を書き換え、L4 の宛先ポートを書き換え
            ipheader.dest_addr = entry.local_ip_addr;
            match proto {
                NatProtocolType::Udp => udpheader.dest_port = entry.local_port,
                NatProtocolType::Tcp => tcpheader.dest_port = entry.local_port,
                NatProtocolType::Icmp => {}
            }

            // チェックサム差分更新
            let mut checksum = match proto {
                NatProtocolType::Udp => udpheader.checksum as u32,
                NatProtocolType::Tcp => tcpheader.checksum as u32,
                NatProtocolType::Icmp => 0,
            } ^ 0xFFFF;

            let mut ipchecksum = (ipheader.header_checksum as u32) ^ 0xFFFF;

            // 目的地 (global→local) に差し替え
            // 32bit IP と 16bit Port の差分を 1の補数和に反映
            checksum = checksum.wrapping_add(entry.local_ip_addr.wrapping_sub(entry.global_ip_addr));
            checksum = checksum.wrapping_add((entry.local_port as u32).wrapping_sub(entry.global_port as u32));
            checksum = (checksum & 0xFFFF) + (checksum >> 16);

            ipchecksum = ipchecksum.wrapping_add(entry.local_ip_addr.wrapping_sub(entry.global_ip_addr));
            ipheader.header_checksum = !(ipchecksum as u16);

            // L4 再配置
            return Ok(match proto {
                NatProtocolType::Udp => {
                    udpheader.checksum = !(checksum as u16);
                    udpheader.to_packet()
                }
                NatProtocolType::Tcp => {
                    tcpheader.checksum = !(checksum as u16);
                    tcpheader.to_packet()
                }
                NatProtocolType::Icmp => unreachable!(),
            });
        }

        NatDirectionType::Outgoing => {
            // 内→外：ローカル (srcIP, srcPort) で引いて、なければエントリ作成
            let maybe_entry = natdevice
                .nat_entry
                .get_nat_entry_by_local(proto, ipheader.src_addr, src_port);

            // 既存 or 新規
            let mut entry = if let Some(e) = maybe_entry {
                e
            } else {
                // 空きスロットに作成
                if let Some(ent_mut) = natdevice.nat_entry.create_nat_entry(proto) {
                    ent_mut.global_ip_addr = natdevice.outside_ip_addr;
                    ent_mut.local_ip_addr = ipheader.src_addr;
                    ent_mut.local_port = match proto {
                        NatProtocolType::Udp => src_port,
                        NatProtocolType::Tcp => src_port,
                        NatProtocolType::Icmp => 0,
                    };
                    println!(
                        "Now, nat entry local {}:{} to global {}:{}",
                        print_ip_addr(ent_mut.local_ip_addr),
                        ent_mut.local_port,
                        print_ip_addr(ent_mut.global_ip_addr),
                        ent_mut.global_port
                    );
                    ent_mut.clone()
                } else {
                    return Err("NAT table is full".into());
                }
            };

            // 送信元 (local→global) に差し替え
            ipheader.src_addr = entry.global_ip_addr;
            match proto {
                NatProtocolType::Udp => {
                    udpheader.src_port = entry.global_port;
                }
                NatProtocolType::Tcp => {
                    tcpheader.src_port = entry.global_port;
                }
                NatProtocolType::Icmp => {}
            }

            // チェックサム差分更新
            let mut checksum = match proto {
                NatProtocolType::Udp => udpheader.checksum as u32,
                NatProtocolType::Tcp => tcpheader.checksum as u32,
                NatProtocolType::Icmp => 0,
            } ^ 0xFFFF;

            let mut ipchecksum = (ipheader.header_checksum as u32) ^ 0xFFFF;

            checksum = checksum.wrapping_sub(entry.local_ip_addr.wrapping_sub(entry.global_ip_addr));
            checksum = checksum.wrapping_sub((entry.local_port as u32).wrapping_sub(entry.global_port as u32));
            checksum = (checksum & 0xFFFF) + (checksum >> 16);

            ipchecksum = ipchecksum.wrapping_sub(entry.local_ip_addr.wrapping_sub(entry.global_ip_addr));
            // Go 版ではここで ipheader.headerChecksum を書き戻していません（その後に別箇所で再計算する想定）。
            // 同じ挙動に合わせてあえて書き戻しはしません。必要なら以下を有効化:
            // ipheader.header_checksum = !(ipchecksum as u16);

            // L4 再配置
            let out = match proto {
                NatProtocolType::Udp => {
                    udpheader.checksum = !(checksum as u16);
                    udpheader.to_packet()
                }
                NatProtocolType::Tcp => {
                    tcpheader.checksum = !(checksum as u16);
                    tcpheader.to_packet()
                }
                NatProtocolType::Icmp => unreachable!(),
            };
            Ok(out)
        }
    }
}