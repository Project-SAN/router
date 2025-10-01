use std::net::Ipv4Addr;
use std::sync::{Mutex, OnceLock};

//定数
pub const IP_ADDRESS_LEN: u8 = 4;
pub const IP_ADDRESS_LIMITED_BROADCAST: u32 = 0xFFFF_FFFF;
pub const IP_PROTOCOL_NUM_ICMP: u8 = 0x01;
pub const IP_PROTOCOL_NUM_TCP: u8 = 0x06;
pub const IP_PROTOCOL_NUM_UDP: u8 = 0x11;

pub const ETHER_TYPE_IP: u16 = 0x0800;
pub const ETHER_TYPE_ARP: u16 = 0x0806;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NatDevice {
    pub outside_ip_addr: u32,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EthernetHeader {
    pub src_addr: [u8; 6],
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IpDevice {
    pub address: u32,
    pub netmask: u32,
    pub broadcast: u32,
    pub natdev: NatDevice,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NetDevice {
    pub name: String,
    pub ipdev: IpDevice,
    pub ethe_header: EthernetHeader,
    pub macaddr: [u8; 6],
}

static NET_DEVICE_LIST: OnceLock<Mutex<Vec<NetDevice>>> = OnceLock::new();
fn net_device_list() -> &'static Mutex<Vec<NetDevice>> {
    NET_DEVICE_LIST.get_or_init(|| Mutex::new(Vec::new()))
}

//arpまわり
fn search_arp_table_entry(_ipaddr: u32) -> ([u8; 6], Option<NetDevice>) {
    ([0; 6], None)
}

fn add_arp_table_entry(_dev: &NetDevice, _ipaddr: u32, _macaddr: [u8; 6]) {

}

fn send_arp_request(_dev: &NetDevice, _target_ip: u32) {

}

//ethernet送信
fn ethernet_output(_dev: &NetDevice, _dst_mac: [u8; 6], _payload: &[u8], _ethertype: u16) {

}

//NATまわり
#[device(Clone, Copy)]
enum NatProto {
    Udp,
    Tcp,
}
#[device(Clone, Copy)]
enum NatDir {
    Outgoing,
    Incoming,
}
struct NatPacketHeader<'a> {
    packet: &'a [u8],
}

fn nat_exec(
    _ip: &IpHeader,
    _pkt: NatPacketHeader<'_>,
    _natdev: &NatDevice,
    _proto: NatProto,
    _dir: NatDir,
) -> Result<Vec<u8>, String> {
    Ok(_pkt.packet.to_vec())
}

//ルーティング
#[device(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IpRouteType {
    Connected,
    Network,
}

#[device(Clone, Debug, Default, PartialEq, Eq)]
pub struct IpRouteEntry {
    pub iptype: IpRouteType,
    pub netdev: NetDevice,
    pub nexthop: u32,
}

//簡易ルート表
#[device(Clone, Default)]
pub struct RouteTable;
impl RouteTable {
    pub fn radix_tree_search(&self, _dest: u32) -> IpRouteEntry {
        IpRouteEntry::default()
    }
}
static IPROUTE: OnceLock<RouteTable> = OnceLock::new();
fn iproute() -> &'static RouteTable {
    IPROUTE.get_or_init(RouteTable::default)
}

//IPヘッダとユーティリティ
#[device(CLone, Debug, Default)]
pub struct IpHeader {
    pub version: u8,
    pub header_len: u8,
    pub tos: u8,
    pub total_len: u16,
    pub identify: u16,
    pub frag_offset: u16,
    pub ttl: u8,
    pub protocol: u8,
    pub header_checksum: u16,
    pub src_addr: u32,
    pub dest_addr: u32,
}

impl IpHeader {
    pub fn to_packet(&self, calc: bool) -> Vec<u8> {
        let mut b = Vec::with_capacity(20);
        b.push((self.version << 4) + self.header_len);
        b.push(self.tos);
        b.extend_from_slice(&self.total_len.to_be_bytes());
        b.extend_from_slice(&self.identify.to_be_bytes());
        b.extend_from_slice(&self.frag_offset.to_be_bytes());
        b.push(self.ttl);
        b.push(self.protocol);
        b.extend_from_slice(&self.header_checksum.to_be_bytes());
        b.extend_from_slice(&self.src_addr.to_be_bytes());
        b.extend_from_slice(&self.dest_addr.to_be_bytes());

        if calc {
            b[10] = 0;
            b[11] = 0;
            let csum = calc_checksum(&b);
            b[10] = csum[0];
            b[11] = csum[1];
        }
        b
    }
}

fn calc_checksum(buf: &[u8]) -> [u8; 2] {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < buf.len() {
        let word = u16::from_be_bytes([buf[i], buf[i + 1]]) as u32;
        sum = sum.wrapping_add(word);
        i += 2;
    }
    if i < buf.len() {
        sum = sum.wrapping_add((buf[i] as u32) << 8);
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    (!sum as u16).to_be_bytes()
}

fn print_ip_addr(ip: u32) -> String {
    let b = ip.to_be_bytes();
    format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3])
}

pub fn subnet_to_prefix_len(netmask: u32) -> u32 {
    let mut prefix = 0;
    while prefix < 32 {
        if((netmask >> (31 - prefix)) & 1) != 1 {
            break;
        }
        prefix += 1;
    }
    prefix
}

pub fn get_ip_device(cidrs: &[&str]) -> IpDevice {
    let mut ipdev = IpDevice::default();
    for cidr in cides {
        if let Some((ip_s, pfx_s)) = cidr.split_once('/') {
            if let Ok(ip) = ip_s.parse::<Ipv4Addr>() {
                if let Ok(pfx) = pfx_s.parse::<u8>() {
                    let mask = (!0u32).checked_shl(32 - pfx as u32).unwrap_or(0);
                    ipdev.address = u32::from(ip);
                    ipdev.netmask = mask.to_be();
                    ipdev.broadcast = ipdev.address | (!ipdev.netmask);
                    break;
                }
            }
        }
    }
    ipdev
}

//IP入力処理
pub fn ip_input(inputdev: &NetDevice, packet: &[u8]) {
    if inputdev.ipdev.address == 0 {
        return;
    }
    if packet.len() < 20 {
        eprintln!("Received IP packet too short from {}", inputdev.name);
        return;
    }

    let ipheader = IpHeader {
        version: packet[0] >> 4,
        header_len: packet[0] & 0x0F,
        tos: packet[1],
        total_len: u16::from_be_bytes([packet[2], packet[3]]),
        identify: u16::from_be_bytes([packet[4], packet[5]]),
        frag_offset: u16::from_be_bytes([packet[6], packet[7]]),
        ttl: packet[8],
        protocol: packet[9],
        header_checksum: u16::from_be_bytes([packet[10], packet[11]]),
        src_addr: u32::from_be_bytes([packet[12], packet[13], packet[14], packet[15]]),
        dest_addr: u32::from_be_bytes([packet[16], packet[17], packet[18], packet[19]]),
    };

    println!(
        "ipInput Received IP in {}, packet type {} from {} to {}",
        inputdev.name,
        ipheader.protocol,
        print_ip_addr(ipheader.src_addr),
        print_ip_addr(ipheader.dest_addr)
    );

    //受信したMACがARPテーブルに無ければ追加
    let (macaddr, _) = search_arp_table_entry(ipheader.src_addr);
    if macaddr == [0u8; 6] {
        add_arp_table_entry(inputdev, ipheader.src_addr, inputdev.ethe_header.src_addr);
    }

    if ipheader.version != 4 {
        if ipheader.version == 6 {
            println!("packet is IPv6");
        } else {
            println!("Incorrect IP version");
        }
        return;
    }

    if 20 < (ipheader.header_len as usize * 4) {
        println!("IP header option is not suported");
        return;
    }

    //自分宛orリミテッドブロードキャスト
    if ipheader.dest_addr == IP_ADDRESS_LIMITED_BROADCAST || inputdev.ipdev.address == ipheader.dest_addr
    {
        ip_input_to_ours(inputdev, &ipheader, &packet[20..]);
        return;
    }

    //ルーターが持っている他のIF宛
    for dev in net_device_list().lock().unwrap().iter() {
        if dev.ipdev.address == ipheader.dest_addr || dev.ipdev.broadcast == ipheader.dest_addr {
            ip_input_to_ours(inputdev, &ipheader, &packet[20..]);
            return;
        }
    }

    //NAT
    let mut nat_packet: Vec<u8> = Vec::new();
    if inputdev.ipdev.natdev != NatDevice::default() {
        let res = match ipheader.protocol {
            IP_PROTOCOL_NUM_UDP => nat_exec (
                &ipheader,
                NatPacketHeader { packet: &packet[20..] },
                &inputdev.ipdev.natdev,
                NatProto::Udp,
                NatDir::Outgoing,
            ),
            IP_PROTOCOL_NUM_TCP => nat_exec (
                &ipheader,
                NatPacketHeader { packet: &packet[20..] },
                &inputdev.ipdev.natdev,
                NatProto::Tcp,
                NatDir::Outgoing,
            ),
            _ => Ok(Vec::new()),
        };
        match res {
            Ok(p) => nat_packet = p,
            Err(e) => {
                eprintln!("nat packet err: {}", e);
                return;
            }
        }
    }

    //ルーティング
    let route = iproute().radix_tree_search(ipheader.dest_addr);
    if route == IpRouteEntry::default() {
        eprintln!("No route to host: {}", print_ip_addr(ipheader.dest_addr));
        return;
    }

    //TTL処理
    if ipheader.ttl <= 1 {
        //ToDo: ICMP Time Exceeded
        return;
    }
    let mut ipheader2 = ipheader.clone();
    ipheader2.ttl -= 1;
    ipheader2.header_checksum = 0;
    ipheader2.header_checksum = u16::from_be_bytes(calc_checksum(&ipheader2.to_packet(true)[..]));

    let mut forward_packet = ipheader2.to_packet(true);
    if inputdev.ipdev.natdev != NatDevice::default() {
        forward_packet.extend_from_slice(&nat_packet);
    } else {
        forward_packet.extend_from_slice(&packet[20..]);
    }

    match route.iptype {
        IpRouteType::Connected => {
            ip_packet_output_to_host(&route.netdev, ipheader2.dest_addr, &forward_packet);
        }
        IpRouteType::Network => {
            println!("next hop is {}", print_ip_addr(route.nexthop));
            println!(
                "forward packet is {:x?} : {:x?}",
                &forward_packet[0..20],
                net_packet
            );
            ip_packet_output_to_nexthop(route.nexthop, &forward_packet);
        }
    }
}

//自分宛処理
fn ip_input_to_ours(inputdev: &NetDevice, ipheader: &IpHeader, payload: &[u8]) {
    for dev in net_device_list().lock().unwrap().iter() {
        if dev.ipdev != IpDevice::default()
            && dev.ipdev.natdev != NatDevice::default()
            && dev.ipdev,natdev.outside_ip_addr == ipheader.dest_addr
        {
            let mut nat_exected = falst;
            let mut dest_packet = Vec::new();
            let res = match ipheader.protocol {
                IP_PROTOCOL_NUM_UDP => nat_exec (
                    ipheader,
                    NatPacketHeader { packet: payload },
                    dev.ipdev.natdev.clone(),
                    NatProto::Udp,
                    NatDir::Incoming,
                ),
                IP_PROTOCOL_NUM_TCP => nat_exec (
                    ipheader,
                    NatPacketHeader { packet: payload },
                    dev.ipdev.natdev.clone(),
                    NatProto::Tcp,
                    NatDir::Incoming,
                ),
                _ => Ok(Vec::new()),
            };
            if let Ok(p) = res {
                if !p.is_empty() {
                    nat_exected = true;
                    dest_packet = p;
                }
            } else {
                return,
            }

            if nat_exected {
                let mut ip_packet = ipheader.to_packet(false);
                ip_packet.extend_from_slice(&dest_packet);
                println!(
                    "To dest is {}, checksum is {:x}, packet is {:x?}",
                    print_ip_addr(ipheader.dest_addr),
                    ipheader.header_checksum,
                    ip_packet
                );
                ip_packet_output(dev, iproute().clone(), ipheader.dest_addr, &ip_packet);
                return;
            }
        }
    }

    //上位プロトコルへ
    match ipheader.protocol {
        IP_PROTOCOL_NUM_ICMP => {
            println!("ICMP received!");
            icmp_input(inputdev, ipheader.src_addr, ipheader.dest_addr, payload);
        }
        IP_PROTOCOL_NUM_UDP => {
            println!("udp received : {:x?}", payload);
        }
        IP_PROTOCOL_NUM_TCP => {
            //ToDo: TCP
        }
        _ => {
            println!("Unhandled ip protocol number: {}", ipheader.protocol);
        }
    }
}

//送信系
fn ip_packet_output_to_host(dev: &NetDevice, dest_addr: u32, packet: &[u8]) {
    let (dest_mac, _) = search_arp_table_entry(dest_addr);
    if dest_mac == [0u8; 6] {
        println!(
            "Trying ip output to host, but no arp recoed to {}",
            print_ip_addr(dest_addr)
        );
        send_arp_request(dev, dest_addr);
    } else {
        ethernet_output(dev, dest_mac, packet, ETHER_TYPE_IP);
    }
}

fn ip_packet_output_to_nexthop(next_hop: u32, packet: &[u8]) {
    let (dest_mac, dev) = search_arp_table_entry(next_hop);
    if dest_mac == [0u8; 6] {
        println!(
            "Trying ip output to nexthop, but no arp recoed to {}",
            print_ip_addr(next_hop)
        );
        let route_to_nexthop = iproute().radix_tree_search(next_hop);
        if route_to_nexthop == IpRouteEntry::default() || route_to_nexthop.iptype != IpRouteType::Connected 
        {
            println!("Next hop {} is not reachable", print_ip_addr(next?hop));
        } else {
            send_arp_request(&route_to_nexthop.netdev, next_hop);
        }
    } else if let Some(dev) = dev {
        ethernet_output(&dev, dest_mac, packet, ETHER_TYPE_IP);
    }
}

fn ip_packet_output(outputdev: &NetDevice, route_tree: RouteTable, dest_addr: u32, packet: &[u8]) {
    let route = route_tree.radix_tree_search(dest_addr);
    if route == IpRouteEntry::default() {
        println!("No route to {}", print_ip_addr(dest_addr));
        return;
    }
    match route.iptype {
        IpRouteType::Connected => {
            ip_packet_output_to_host(outputdev, dest_addr, packet);
        }
        IpRouteType::Network => {
            ip_packet_output_to_nexthop(dest_addr, packet);
        }
    }
}

//IPをカプセル化して送信
pub fn ip_packet_encapsulate_output(
    inputdev: &NetDevice,
    dest_addr: u32,
    src_addr: u32,
    payload: &[u8],
    protocol_type: u8,
) {
    let total_len = 20 + payload.len();
    let mut ipheader = IpHeader {
        version: 4,
        header_len: 20 / 4,
        tos: 0,
        total_len: total_len as u16,
        identify: 0xf80c,
        frag_offset: 2 << 13,
        ttl: 0x40,
        protocol: protocol_type,
        header_checksum: 0,
        src_addr,
        dest_addr,
    };
    let mut ip_packet = ipheader.to_packet(true);
    ip_packet.extend_from_slice(payload);

    let (dest_mac, _) = search_arp_table_entry(dest_addr);
    if dest_mac != [0u8; 6] {
        ethernet_output(inputdev, dest_mac, &ip_packet, ETHER_TYPE_IP);
    } else {
        send_arp_request(inputdev, dest_addr);
    }
}

//ICMP入力
fn icmp_input(_dev: &NetDevice, _src: u32, _dst: u32, _icmp: &[u8]) {
    // 既に用意済みの icmp.rs の icmp_input をここにリンクしてください
    println!("(stub) icmp_input called, len={}", _icmp.len());
}