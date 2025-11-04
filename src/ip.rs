use crate::arp;
use crate::hornet_runtime::{self, ProcessOutcome};
use crate::icmp;
use crate::nat;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex, OnceLock};

//定数
pub const IP_ADDRESS_LEN: u8 = 4;
pub const IP_ADDRESS_LIMITED_BROADCAST: u32 = 0xFFFF_FFFF;
pub const IP_PROTOCOL_NUM_ICMP: u8 = 0x01;
pub const IP_PROTOCOL_NUM_TCP: u8 = 0x06;
pub const IP_PROTOCOL_NUM_UDP: u8 = 0x11;

pub const ETHER_TYPE_IP: u16 = 0x0800;
pub const ETHER_TYPE_ARP: u16 = 0x0806;

#[derive(Clone, Debug)]
pub struct NatDevice {
    pub outside_ip_addr: u32,
    role: NatInterfaceRole,
    state: Option<Arc<Mutex<nat::NatDevice>>>,
}

impl PartialEq for NatDevice {
    fn eq(&self, other: &Self) -> bool {
        self.outside_ip_addr == other.outside_ip_addr && self.role == other.role
    }
}

impl Eq for NatDevice {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NatInterfaceRole {
    None,
    Inside,
    Outside,
}

impl Default for NatDevice {
    fn default() -> Self {
        Self {
            outside_ip_addr: 0,
            role: NatInterfaceRole::None,
            state: None,
        }
    }
}

impl NatDevice {
    pub(crate) fn for_inside(outside_ip_addr: u32, state: Arc<Mutex<nat::NatDevice>>) -> Self {
        Self {
            outside_ip_addr,
            role: NatInterfaceRole::Inside,
            state: Some(state),
        }
    }

    pub(crate) fn for_outside(outside_ip_addr: u32, state: Arc<Mutex<nat::NatDevice>>) -> Self {
        Self {
            outside_ip_addr,
            role: NatInterfaceRole::Outside,
            state: Some(state),
        }
    }

    fn is_inside(&self) -> bool {
        matches!(self.role, NatInterfaceRole::Inside)
    }

    pub(crate) fn shared_state(&self) -> Option<Arc<Mutex<nat::NatDevice>>> {
        self.state.as_ref().map(Arc::clone)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EthernetHeader {
    pub src_addr: [u8; 6],
    pub dest_addr: [u8; 6],
    pub ether_type: u16,
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
fn search_arp_table_entry(ipaddr: u32) -> ([u8; 6], Option<NetDevice>) {
    arp::search_arp_table_entry(ipaddr)
}

fn add_arp_table_entry(dev: &NetDevice, ipaddr: u32, macaddr: [u8; 6]) {
    arp::add_arp_table_entry(dev, ipaddr, macaddr)
}

fn send_arp_request(dev: &NetDevice, target_ip: u32) {
    arp::send_arp_request(dev, target_ip)
}

//ethernet送信
fn ethernet_output(dev: &NetDevice, dst_mac: [u8; 6], payload: &[u8], ethertype: u16) {
    if let Err(err) = crate::ethernet::ethernet_output(dev, dst_mac, payload, ethertype) {
        eprintln!("failed to transmit ethernet frame on {}: {}", dev.name, err);
    }
}

//NATまわり
#[derive(Clone, Copy)]
enum NatProto {
    Udp,
    Tcp,
}
#[derive(Clone, Copy)]
enum NatDir {
    Outgoing,
    Incoming,
}
struct NatPacketHeader<'a> {
    packet: &'a [u8],
}

fn nat_exec(
    ip: &mut IpHeader,
    pkt: NatPacketHeader<'_>,
    natdev: &NatDevice,
    proto: NatProto,
    dir: NatDir,
) -> Result<Vec<u8>, String> {
    let Some(state) = natdev.shared_state() else {
        return Ok(pkt.packet.to_vec());
    };
    let mut guard = state
        .lock()
        .map_err(|_| "nat state is poisoned".to_string())?;

    let mut nat_header = nat::IpHeader {
        header_checksum: ip.header_checksum,
        src_addr: ip.src_addr,
        dest_addr: ip.dest_addr,
    };

    let nat_proto = match proto {
        NatProto::Udp => nat::NatProtocolType::Udp,
        NatProto::Tcp => nat::NatProtocolType::Tcp,
    };

    let nat_dir = match dir {
        NatDir::Outgoing => nat::NatDirectionType::Outgoing,
        NatDir::Incoming => nat::NatDirectionType::Incoming,
    };

    let result = nat::nat_exec(
        &mut nat_header,
        nat::NatPacketHeader { packet: pkt.packet },
        &mut *guard,
        nat_proto,
        nat_dir,
    )?;

    ip.header_checksum = nat_header.header_checksum;
    ip.src_addr = nat_header.src_addr;
    ip.dest_addr = nat_header.dest_addr;

    Ok(result)
}

//ルーティング
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IpRouteType {
    Connected,
    Network,
}

impl Default for IpRouteType {
    fn default() -> Self {
        IpRouteType::Network
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IpRouteEntry {
    pub iptype: IpRouteType,
    pub netdev: NetDevice,
    pub nexthop: u32,
}

//簡易ルート表
#[derive(Clone)]
pub struct RouteTable {
    inner: Arc<Mutex<Vec<RouteRecord>>>,
}

#[derive(Clone, Debug)]
pub struct RouteEntryConfig {
    pub prefix: u32,
    pub prefix_len: u8,
    pub entry: IpRouteEntry,
}

#[derive(Clone, Debug)]
struct RouteRecord {
    prefix: u32,
    prefix_len: u8,
    netmask: u32,
    entry: IpRouteEntry,
}

impl Default for RouteTable {
    fn default() -> Self {
        Self {
            inner: Arc::new(Mutex::new(Vec::new())),
        }
    }
}

impl RouteTable {
    fn replace_routes(&self, routes: Vec<RouteRecord>) -> Result<(), String> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| "route table mutex is poisoned".to_string())?;
        *guard = routes;
        Ok(())
    }

    pub fn radix_tree_search(&self, dest: u32) -> IpRouteEntry {
        let Ok(guard) = self.inner.lock() else {
            return IpRouteEntry::default();
        };

        let mut best: Option<&RouteRecord> = None;
        for record in guard.iter() {
            if (dest & record.netmask) == record.prefix {
                match best {
                    Some(current) if current.prefix_len >= record.prefix_len => {}
                    _ => best = Some(record),
                }
            }
        }
        best.map(|r| r.entry.clone()).unwrap_or_default()
    }
}

static IPROUTE: OnceLock<RouteTable> = OnceLock::new();
fn iproute() -> &'static RouteTable {
    IPROUTE.get_or_init(RouteTable::default)
}

pub fn set_route_entries(routes: Vec<RouteEntryConfig>) -> Result<(), String> {
    let mut records = Vec::with_capacity(routes.len());
    for route in routes {
        let Some(netmask) = prefix_to_netmask(route.prefix_len) else {
            return Err(format!("invalid prefix length {}", route.prefix_len));
        };
        records.push(RouteRecord {
            prefix: route.prefix & netmask,
            prefix_len: route.prefix_len,
            netmask,
            entry: route.entry.clone(),
        });
    }
    iproute().replace_routes(records)
}

//IPヘッダとユーティリティ
#[derive(Clone, Debug, Default)]
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

struct ParsedUdp<'a> {
    src_port: u16,
    dest_port: u16,
    payload: &'a [u8],
}

fn parse_udp_packet(packet: &[u8]) -> Option<ParsedUdp<'_>> {
    if packet.len() < 8 {
        return None;
    }
    let src_port = u16::from_be_bytes([packet[0], packet[1]]);
    let dest_port = u16::from_be_bytes([packet[2], packet[3]]);
    let length = u16::from_be_bytes([packet[4], packet[5]]) as usize;
    if length < 8 || length > packet.len() {
        return None;
    }
    let payload_len = length - 8;
    if payload_len > packet.len() - 8 {
        return None;
    }
    let payload = &packet[8..8 + payload_len];
    Some(ParsedUdp {
        src_port,
        dest_port,
        payload,
    })
}

fn build_udp_segment(
    src_ip: u32,
    dest_ip: u32,
    src_port: u16,
    dest_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let length = (8 + payload.len()) as u16;
    let mut segment = Vec::with_capacity(length as usize);
    segment.extend_from_slice(&src_port.to_be_bytes());
    segment.extend_from_slice(&dest_port.to_be_bytes());
    segment.extend_from_slice(&length.to_be_bytes());
    segment.extend_from_slice(&0u16.to_be_bytes()); // checksum placeholder
    segment.extend_from_slice(payload);

    let checksum = udp_checksum(src_ip, dest_ip, IP_PROTOCOL_NUM_UDP, &segment);
    segment[6] = (checksum >> 8) as u8;
    segment[7] = (checksum & 0xFF) as u8;
    segment
}

fn udp_checksum(src_ip: u32, dest_ip: u32, protocol: u8, segment: &[u8]) -> u16 {
    let mut pseudo = Vec::with_capacity(12 + segment.len());
    pseudo.extend_from_slice(&src_ip.to_be_bytes());
    pseudo.extend_from_slice(&dest_ip.to_be_bytes());
    pseudo.push(0);
    pseudo.push(protocol);
    pseudo.extend_from_slice(&(segment.len() as u16).to_be_bytes());
    pseudo.extend_from_slice(segment);
    if pseudo.len() % 2 != 0 {
        pseudo.push(0);
    }
    u16::from_be_bytes(calc_checksum(&pseudo))
}

fn ipv4_to_u32(addr: Ipv4Addr) -> u32 {
    u32::from_be_bytes(addr.octets())
}

fn find_device_by_name(name: &str) -> Option<NetDevice> {
    net_device_list()
        .lock()
        .ok()
        .and_then(|guard| guard.iter().find(|d| d.name == name).cloned())
}

pub fn print_ip_addr(ip: u32) -> String {
    let b = ip.to_be_bytes();
    format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3])
}

fn prefix_to_netmask(prefix: u8) -> Option<u32> {
    if prefix > 32 {
        return None;
    }
    if prefix == 0 {
        return Some(0);
    }
    Some((!0u32).checked_shl(32 - prefix as u32).unwrap_or(0))
}

pub fn subnet_to_prefix_len(netmask: u32) -> u32 {
    let mut prefix = 0;
    while prefix < 32 {
        if ((netmask >> (31 - prefix)) & 1) != 1 {
            break;
        }
        prefix += 1;
    }
    prefix
}

pub fn get_ip_device(cidrs: &[&str]) -> IpDevice {
    let mut ipdev = IpDevice::default();
    for cidr in cidrs {
        if let Some((ip_s, pfx_s)) = cidr.split_once('/') {
            if let Ok(ip) = ip_s.parse::<Ipv4Addr>() {
                if let Ok(pfx) = pfx_s.parse::<u8>() {
                    let mask = (!0u32).checked_shl(32 - pfx as u32).unwrap_or(0);
                    ipdev.address = u32::from(ip);
                    ipdev.netmask = mask;
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
    println!(
        "ip_input entry dev={} addr={:08x} len={}",
        inputdev.name,
        inputdev.ipdev.address,
        packet.len()
    );
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
    if ipheader.dest_addr == IP_ADDRESS_LIMITED_BROADCAST
        || inputdev.ipdev.address == ipheader.dest_addr
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

    //ルーティング
    let route = iproute().radix_tree_search(ipheader.dest_addr);
    if route == IpRouteEntry::default() {
        eprintln!("No route to host: {}", print_ip_addr(ipheader.dest_addr));
        send_icmp_destination_unreachable(inputdev, &ipheader, packet);
        return;
    }

    //TTL処理
    if ipheader.ttl <= 1 {
        //ToDo: ICMP Time Exceeded
        send_icmp_time_exceeded(inputdev, &ipheader, packet);
        return;
    }
    let mut ipheader2 = ipheader.clone();
    ipheader2.ttl -= 1;
    ipheader2.header_checksum = 0;

    let mut translated_payload: Option<Vec<u8>> = None;
    if inputdev.ipdev.natdev.is_inside() {
        println!(
            "applying NAT on {} toward {} (protocol {})",
            inputdev.name,
            print_ip_addr(ipheader2.dest_addr),
            ipheader2.protocol
        );
        let res = match ipheader2.protocol {
            IP_PROTOCOL_NUM_UDP => nat_exec(
                &mut ipheader2,
                NatPacketHeader {
                    packet: &packet[20..],
                },
                &inputdev.ipdev.natdev,
                NatProto::Udp,
                NatDir::Outgoing,
            ),
            IP_PROTOCOL_NUM_TCP => nat_exec(
                &mut ipheader2,
                NatPacketHeader {
                    packet: &packet[20..],
                },
                &inputdev.ipdev.natdev,
                NatProto::Tcp,
                NatDir::Outgoing,
            ),
            _ => Ok(Vec::new()),
        };
        match res {
            Ok(p) if !p.is_empty() => translated_payload = Some(p),
            Ok(_) => {}
            Err(e) => {
                eprintln!("nat packet err: {}", e);
                return;
            }
        }
    }

    ipheader2.header_checksum = u16::from_be_bytes(calc_checksum(&ipheader2.to_packet(true)[..]));

    let mut forward_packet = ipheader2.to_packet(true);
    let outbound_payload = translated_payload
        .as_ref()
        .map(|p| p.as_slice())
        .unwrap_or(&packet[20..]);
    forward_packet.extend_from_slice(outbound_payload);

    match route.iptype {
        IpRouteType::Connected => {
            ip_packet_output_to_host(&route.netdev, ipheader2.dest_addr, &forward_packet);
        }
        IpRouteType::Network => {
            println!("next hop is {}", print_ip_addr(route.nexthop));
            println!(
                "forward packet is {:x?} : {:x?}",
                &forward_packet[0..20],
                outbound_payload
            );
            ip_packet_output_to_nexthop(&route.netdev, route.nexthop, &forward_packet);
        }
    }
}

//自分宛処理
fn ip_input_to_ours(inputdev: &NetDevice, ipheader: &IpHeader, payload: &[u8]) {
    for dev in net_device_list().lock().unwrap().iter() {
        if dev.ipdev != IpDevice::default()
            && dev.ipdev.natdev.is_inside()
            && dev.ipdev.natdev.outside_ip_addr == ipheader.dest_addr
        {
            let mut rewritten_header = ipheader.clone();
            let mut rewritten_payload: Option<Vec<u8>> = None;
            let res = match rewritten_header.protocol {
                IP_PROTOCOL_NUM_UDP => nat_exec(
                    &mut rewritten_header,
                    NatPacketHeader { packet: payload },
                    &dev.ipdev.natdev,
                    NatProto::Udp,
                    NatDir::Incoming,
                ),
                IP_PROTOCOL_NUM_TCP => nat_exec(
                    &mut rewritten_header,
                    NatPacketHeader { packet: payload },
                    &dev.ipdev.natdev,
                    NatProto::Tcp,
                    NatDir::Incoming,
                ),
                _ => Ok(Vec::new()),
            };
            match res {
                Ok(p) => {
                    if !p.is_empty() {
                        rewritten_payload = Some(p);
                    }
                }
                Err(e) => {
                    eprintln!("nat packet err: {}", e);
                    return;
                }
            }

            let mut ip_packet = rewritten_header.to_packet(false);
            if let Some(payload_bytes) = rewritten_payload {
                ip_packet.extend_from_slice(&payload_bytes);
            } else {
                ip_packet.extend_from_slice(payload);
            }
            println!(
                "To dest is {}, checksum is {:x}, packet is {:x?}",
                print_ip_addr(rewritten_header.dest_addr),
                rewritten_header.header_checksum,
                ip_packet
            );
            println!(
                "incoming NAT delivered to {} (protocol {})",
                dev.name, rewritten_header.protocol
            );
            ip_packet_output(iproute().clone(), rewritten_header.dest_addr, &ip_packet);
            return;
        }
    }

    //上位プロトコルへ
    match ipheader.protocol {
        IP_PROTOCOL_NUM_ICMP => {
            println!("ICMP received!");
            icmp_input(inputdev, ipheader.src_addr, ipheader.dest_addr, payload);
        }
        IP_PROTOCOL_NUM_UDP => {
            if let Some(udp) = parse_udp_packet(payload) {
                if let Some(processed) = hornet_runtime::handle_udp_packet(
                    Ipv4Addr::from(ipheader.src_addr),
                    udp.src_port,
                    Ipv4Addr::from(ipheader.dest_addr),
                    udp.dest_port,
                    udp.payload,
                ) {
                    match processed {
                        Ok(ProcessOutcome::Forward(packet)) => {
                            let src_addr = ipheader.dest_addr;
                            let dest_addr = ipv4_to_u32(packet.next_addr);
                            let override_dev = packet
                                .interface
                                .as_ref()
                                .and_then(|name| find_device_by_name(name));
                            let output_dev = override_dev.as_ref().unwrap_or(inputdev);
                            let udp_segment = build_udp_segment(
                                src_addr,
                                dest_addr,
                                packet.source_port,
                                packet.next_port,
                                &packet.wire_payload,
                            );
                            ip_packet_encapsulate_output(
                                output_dev,
                                dest_addr,
                                src_addr,
                                &udp_segment,
                                IP_PROTOCOL_NUM_UDP,
                            );
                            return;
                        }
                        Ok(ProcessOutcome::Consumed) => {
                            return;
                        }
                        Ok(ProcessOutcome::NotHandled) => { /* continue */ }
                        Err(err) => {
                            eprintln!("HORNET processing error: {}", err);
                            return;
                        }
                    }
                }
            }
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
        arp::queue_pending_packet(dev, dest_addr, ETHER_TYPE_IP, packet);
        send_arp_request(dev, dest_addr);
    } else {
        ethernet_output(dev, dest_mac, packet, ETHER_TYPE_IP);
    }
}

fn ip_packet_output_to_nexthop(netdev: &NetDevice, next_hop: u32, packet: &[u8]) {
    let (dest_mac, dev) = search_arp_table_entry(next_hop);
    if dest_mac == [0u8; 6] {
        println!(
            "Trying ip output to nexthop, but no arp recoed to {}",
            print_ip_addr(next_hop)
        );
        arp::queue_pending_packet(netdev, next_hop, ETHER_TYPE_IP, packet);
        send_arp_request(netdev, next_hop);
    } else if let Some(dev) = dev {
        ethernet_output(&dev, dest_mac, packet, ETHER_TYPE_IP);
    } else {
        ethernet_output(netdev, dest_mac, packet, ETHER_TYPE_IP);
    }
}

fn ip_packet_output(route_tree: RouteTable, dest_addr: u32, packet: &[u8]) {
    let route = route_tree.radix_tree_search(dest_addr);
    if route == IpRouteEntry::default() {
        println!("No route to {}", print_ip_addr(dest_addr));
        return;
    }
    match route.iptype {
        IpRouteType::Connected => {
            ip_packet_output_to_host(&route.netdev, dest_addr, packet);
        }
        IpRouteType::Network => {
            ip_packet_output_to_nexthop(&route.netdev, route.nexthop, packet);
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
    let ipheader = IpHeader {
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
        arp::queue_pending_packet(inputdev, dest_addr, ETHER_TYPE_IP, &ip_packet);
        send_arp_request(inputdev, dest_addr);
    }
}

fn send_icmp_destination_unreachable(
    inputdev: &NetDevice,
    ipheader: &IpHeader,
    original_packet: &[u8],
) {
    send_icmp_error(
        inputdev,
        ipheader,
        original_packet,
        icmp::ICMP_TYPE_DESTINATION_UNREACHABLE,
        1,
    );
}

fn send_icmp_time_exceeded(inputdev: &NetDevice, ipheader: &IpHeader, original_packet: &[u8]) {
    send_icmp_error(
        inputdev,
        ipheader,
        original_packet,
        icmp::ICMP_TYPE_TIME_EXCEEDED,
        0,
    );
}

fn send_icmp_error(
    inputdev: &NetDevice,
    ipheader: &IpHeader,
    original_packet: &[u8],
    icmp_type: u8,
    icmp_code: u8,
) {
    if ipheader.src_addr == 0 {
        return;
    }

    let header_len_bytes = (ipheader.header_len as usize) * 4;
    if original_packet.len() < header_len_bytes {
        return;
    }
    let copy_len = (header_len_bytes + 8).min(original_packet.len());

    let mut icmp_packet = Vec::with_capacity(8 + copy_len);
    icmp_packet.push(icmp_type);
    icmp_packet.push(icmp_code);
    icmp_packet.extend_from_slice(&[0, 0]); // checksum placeholder
    icmp_packet.extend_from_slice(&[0, 0, 0, 0]); // unused field
    icmp_packet.extend_from_slice(&original_packet[..copy_len]);

    let checksum = calc_checksum(&icmp_packet);
    icmp_packet[2] = checksum[0];
    icmp_packet[3] = checksum[1];

    ip_packet_encapsulate_output(
        inputdev,
        ipheader.src_addr,
        inputdev.ipdev.address,
        &icmp_packet,
        IP_PROTOCOL_NUM_ICMP,
    );
}

//ICMP入力
fn icmp_input(dev: &NetDevice, src: u32, dst: u32, icmp_packet: &[u8]) {
    icmp::icmp_input(dev, src, dst, icmp_packet);
}

pub fn set_net_devices(devices: Vec<NetDevice>) -> Result<(), String> {
    let list = net_device_list();
    let mut guard = list
        .lock()
        .map_err(|_| "net_device_list mutex is poisoned".to_string())?;
    *guard = devices;
    Ok(())
}

pub fn get_net_devices() -> Result<Vec<NetDevice>, String> {
    let list = net_device_list();
    let guard = list
        .lock()
        .map_err(|_| "net_device_list mutex is poisoned".to_string())?;
    Ok(guard.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::sync::{Arc, Mutex};

    fn make_device(name: &str) -> NetDevice {
        NetDevice {
            name: name.to_string(),
            ipdev: IpDevice::default(),
            ethe_header: EthernetHeader::default(),
            macaddr: [0u8; 6],
        }
    }

    #[test]
    fn selects_longest_prefix_match() {
        let mut default_dev = make_device("eth0");
        default_dev.ipdev.address = u32::from(Ipv4Addr::new(203, 0, 113, 2));

        let mut lan_dev = make_device("eth1");
        lan_dev.ipdev.address = u32::from(Ipv4Addr::new(192, 168, 10, 1));

        set_route_entries(vec![
            RouteEntryConfig {
                prefix: 0,
                prefix_len: 0,
                entry: IpRouteEntry {
                    iptype: IpRouteType::Network,
                    netdev: default_dev.clone(),
                    nexthop: u32::from(Ipv4Addr::new(203, 0, 113, 1)),
                },
            },
            RouteEntryConfig {
                prefix: u32::from(Ipv4Addr::new(192, 168, 10, 0)),
                prefix_len: 24,
                entry: IpRouteEntry {
                    iptype: IpRouteType::Connected,
                    netdev: lan_dev.clone(),
                    nexthop: 0,
                },
            },
        ])
        .unwrap();

        let table = super::iproute();
        let lan_route = table.radix_tree_search(u32::from(Ipv4Addr::new(192, 168, 10, 42)));
        assert_eq!(lan_route.iptype, IpRouteType::Connected);
        assert_eq!(lan_route.netdev.name, "eth1");

        let default_route = table.radix_tree_search(u32::from(Ipv4Addr::new(8, 8, 8, 8)));
        assert_eq!(default_route.iptype, IpRouteType::Network);
        assert_eq!(
            default_route.nexthop,
            u32::from(Ipv4Addr::new(203, 0, 113, 1))
        );
    }

    #[test]
    fn nat_exec_translates_udp_source() {
        let nat_state = Arc::new(Mutex::new(crate::nat::NatDevice {
            outside_ip_addr: u32::from(Ipv4Addr::new(203, 0, 113, 2)),
            ..Default::default()
        }));

        let nat_dev = NatDevice::for_inside(u32::from(Ipv4Addr::new(203, 0, 113, 2)), nat_state);
        let mut ip_header = IpHeader {
            version: 4,
            header_len: 5,
            tos: 0,
            total_len: 28,
            identify: 0,
            frag_offset: 0,
            ttl: 64,
            protocol: IP_PROTOCOL_NUM_UDP,
            header_checksum: 0,
            src_addr: u32::from(Ipv4Addr::new(192, 168, 10, 10)),
            dest_addr: u32::from(Ipv4Addr::new(203, 0, 113, 1)),
        };

        let udp_payload = {
            let mut buf = Vec::new();
            buf.extend_from_slice(&40001u16.to_be_bytes()); // src port
            buf.extend_from_slice(&8080u16.to_be_bytes()); // dest port
            buf.extend_from_slice(&12u16.to_be_bytes()); // length
            buf.extend_from_slice(&0u16.to_be_bytes()); // checksum placeholder
            buf.extend_from_slice(b"hello test");
            buf
        };

        let translated = nat_exec(
            &mut ip_header,
            NatPacketHeader {
                packet: &udp_payload,
            },
            &nat_dev,
            NatProto::Udp,
            NatDir::Outgoing,
        )
        .expect("nat exec");

        assert_eq!(ip_header.src_addr, u32::from(Ipv4Addr::new(203, 0, 113, 2)));
        assert_ne!(u16::from_be_bytes([translated[0], translated[1]]), 40001u16);
    }
}
