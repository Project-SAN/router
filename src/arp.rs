use crate::ethernet::ethernet_output;
use crate::ip::NetDevice;
use std::collections::HashMap;
use std::fmt::Write as _;
use std::sync::{Mutex, OnceLock};

pub const ARP_OPERATION_CODE_REQUEST: u16 = 1;
pub const ARP_OPERATION_CODE_REPLY: u16 = 2;
pub const ARP_HTYPE_ETHERNET: u16 = 0x0001;

pub const ETHER_TYPE_IP: u16 = 0x0800;
pub const ETHER_TYPE_ARP: u16 = 0x0806;

pub const ETHERNET_ADDRESS_LEN: u8 = 6;
pub const IP_ADDRESS_LEN: u8 = 4;

pub const ETHERNET_ADDRESS_BROADCAST: [u8; 6] = [0xff; 6];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MacAddr(pub [u8; 6]);

//ARPテーブル(global)
#[derive(Clone, Debug)]
pub struct ArpTableEntry {
    pub mac_addr: [u8; 6],
    pub ip_addr: u32,
    pub netdev: NetDevice,
}

static ARP_TABLE: OnceLock<Mutex<Vec<ArpTableEntry>>> = OnceLock::new();

fn arp_table() -> &'static Mutex<Vec<ArpTableEntry>> {
    ARP_TABLE.get_or_init(|| Mutex::new(Vec::new()))
}

#[derive(Clone, Debug)]
struct PendingPacket {
    interface: String,
    ethertype: u16,
    payload: Vec<u8>,
}

static PENDING_QUEUE: OnceLock<Mutex<HashMap<u32, Vec<PendingPacket>>>> = OnceLock::new();

fn pending_packets() -> &'static Mutex<HashMap<u32, Vec<PendingPacket>>> {
    PENDING_QUEUE.get_or_init(|| Mutex::new(HashMap::new()))
}

const MAX_PENDING_PER_IP: usize = 32;

pub fn queue_pending_packet(netdev: &NetDevice, target_ip: u32, ethertype: u16, payload: &[u8]) {
    let mut queue = pending_packets().lock().unwrap();
    let entry = queue.entry(target_ip).or_insert_with(Vec::new);
    if entry.len() >= MAX_PENDING_PER_IP {
        entry.remove(0);
    }
    entry.push(PendingPacket {
        interface: netdev.name.clone(),
        ethertype,
        payload: payload.to_vec(),
    });
}

//ARPメッセージ(Ethernet/IP向け)
#[derive(Clone, Debug)]
pub struct ArpIPToEthernet {
    pub hardware_type: u16,
    pub protocol_type: u16,
    pub hardware_len: u8,
    pub protocol_len: u8,
    pub opcode: u16,
    pub sender_hardware_addr: [u8; 6],
    pub sender_ip_addr: u32,
    pub target_hardware_addr: [u8; 6],
    pub target_ip_addr: u32,
}

//バイト変換ヘルパ
fn u16_to_be_bytes(x: u16) -> [u8; 2] { x.to_be_bytes() }
fn u32_to_be_bytes(x: u32) -> [u8; 4] { x.to_be_bytes() }
fn be_bytes_to_u16(bytes: &[u8]) -> u16 {
    let mut arr = [0u8; 2];
    arr.copy_from_slice(&bytes[0..2]);
    u16::from_be_bytes(arr)
}
fn be_bytes_to_u32(b: &[u8]) -> u32 {
    let mut arr = [0u8; 4];
    arr.copy_from_slice(&b[0..4]);
    u32::from_be_bytes(arr)
}

fn set_mac_addr(slice: &[u8]) -> [u8; 6] {
    let mut m = [0u8; 6];
    m.copy_from_slice(&slice[0..6]);
    m
}

//表示ヘルパ
fn print_ip_addr(ip: u32) -> String {
    let b = ip.to_be_bytes();
    format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3])
}

fn print_mac_addr(mac: [u8; 6]) -> String {
    let mut s = String::new();
    for(i, b) in mac.iter().enumerate() {
        let _ = write!(&mut s, "{:02x}{}", b, if i < 5 { ":" } else { "" });
    }
    s
}

impl ArpIPToEthernet {
    pub fn to_packet(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(28);
        b.extend_from_slice(&u16_to_be_bytes(self.hardware_type));
        b.extend_from_slice(&u16_to_be_bytes(self.protocol_type));
        b.push(self.hardware_len);
        b.push(self.protocol_len);
        b.extend_from_slice(&u16_to_be_bytes(self.opcode));
        b.extend_from_slice(&self.sender_hardware_addr);
        b.extend_from_slice(&u32_to_be_bytes(self.sender_ip_addr));
        b.extend_from_slice(&self.target_hardware_addr);
        b.extend_from_slice(&u32_to_be_bytes(self.target_ip_addr));
        b
    }

    pub fn from_packet(packet: &[u8]) -> Option<Self> {
        if packet.len() < 28 {
            return None;
        }

        Some(Self {
            hardware_type: be_bytes_to_u16(&packet[0..2]),
            protocol_type: be_bytes_to_u16(&packet[2..4]),
            hardware_len: packet[4],
            protocol_len: packet[5],
            opcode: be_bytes_to_u16(&packet[6..8]),
            sender_hardware_addr: set_mac_addr(&packet[8..14]),
            sender_ip_addr: be_bytes_to_u32(&packet[14..18]),
            target_hardware_addr: set_mac_addr(&packet[18..24]),
            target_ip_addr: be_bytes_to_u32(&packet[24..28]),
        })
    }
}

//ARPテーブル操作

pub fn add_arp_table_entry(netdev: &NetDevice, ipaddr: u32, macaddr: [u8; 6]) {
    let mut table = arp_table().lock().unwrap();
    let mut updated = false;

    for entry in table.iter_mut() {
        if entry.ip_addr == ipaddr {
            if entry.mac_addr != macaddr {
                entry.mac_addr = macaddr;
            }
            entry.netdev = netdev.clone();
            updated = true;
            break;
        }
    }

    if !updated {
        table.push(ArpTableEntry {
            mac_addr: macaddr,
            ip_addr: ipaddr,
            netdev: netdev.clone(),
        });
    }

    drop(table);
    flush_pending_packets(ipaddr, macaddr);
}

pub fn search_arp_table_entry(ipaddr: u32) -> ([u8; 6], Option<NetDevice>) {
    let table = arp_table().lock().unwrap();
    for entry in table.iter() {
        if entry.ip_addr == ipaddr {
            return (entry.mac_addr, Some(entry.netdev.clone()));
        }
    }
    ([0u8; 6], None)
}

pub fn snapshot_arp_table() -> Vec<ArpTableEntry> {
    let table = arp_table().lock().unwrap();
    table.clone()
}

fn flush_pending_packets(ipaddr: u32, macaddr: [u8; 6]) {
    let packets = {
        let mut queue = pending_packets().lock().unwrap();
        queue.remove(&ipaddr)
    };

    let Some(packets) = packets else {
        return;
    };

    let Ok(devices) = crate::ip::get_net_devices() else {
        let mut queue = pending_packets().lock().unwrap();
        queue.insert(ipaddr, packets);
        return;
    };

    let mut unsent: Vec<PendingPacket> = Vec::new();

    for packet in packets {
        if let Some(dev) = devices.iter().find(|d| d.name == packet.interface) {
            if let Err(err) = ethernet_output(dev, macaddr, &packet.payload, packet.ethertype) {
                eprintln!(
                    "failed to flush pending packet on {}: {}",
                    dev.name, err
                );
                unsent.push(packet);
            }
        } else {
            eprintln!(
                "dropping pending packet: interface {} not found",
                packet.interface
            );
        }
    }

    if !unsent.is_empty() {
        let mut queue = pending_packets().lock().unwrap();
        queue.entry(ipaddr).or_default().extend(unsent);
    }
}

//arp受信処理
pub fn arp_input(netdev: &NetDevice, packet: &[u8]) {
    if packet.len() < 28 {
        eprintln!("received ARP Packet is too short");
        return;
    }

    let Some(arp_msg) = ArpIPToEthernet::from_packet(packet) else {
        eprintln!("failed to parse ARP packet");
        return;
    };

    match arp_msg.protocol_type {
        ETHER_TYPE_IP => {
            if arp_msg.hardware_len != ETHERNET_ADDRESS_LEN {
                eprintln!("Illegal hardware address length");
                return;
            }
            if arp_msg.protocol_len != IP_ADDRESS_LEN {
                eprintln!("Illegal protocol address length");
                return;
            }

            if arp_msg.opcode == ARP_OPERATION_CODE_REQUEST {
                println!("ARP Request Packet is {:?}", arp_msg);
                arp_request_arrives(netdev, &arp_msg);
            } else {
                println!("ARP Reply Packet is {:?}", arp_msg);
                arp_reply_arrives(netdev, &arp_msg);
            }
        }
        _ => {/*他のプロトコルは無視*/}
    }
}

//ARPリクエスト/リプライ処理
pub fn arp_request_arrives(netdev: &NetDevice, arp: &ArpIPToEthernet) {
    add_arp_table_entry(netdev, arp.sender_ip_addr, arp.sender_hardware_addr);

    if netdev.ipdev.address != 0 && netdev.ipdev.address == arp.target_ip_addr {
        println!(
            "Sendeing arp reply to {}",
            print_ip_addr(arp.target_ip_addr)
        );

        let reply = ArpIPToEthernet {
            hardware_type: ARP_HTYPE_ETHERNET,
            protocol_type: ETHER_TYPE_IP,
            hardware_len: ETHERNET_ADDRESS_LEN,
            protocol_len: IP_ADDRESS_LEN,
            opcode: ARP_OPERATION_CODE_REPLY,
            sender_hardware_addr: netdev.macaddr,
            sender_ip_addr: netdev.ipdev.address,
            target_hardware_addr: arp.sender_hardware_addr,
            target_ip_addr: arp.sender_ip_addr,
        }
        .to_packet();

        if let Err(err) =
            ethernet_output(netdev, arp.sender_hardware_addr, &reply, ETHER_TYPE_ARP)
        {
            eprintln!(
                "failed to send arp reply on {}: {}",
                netdev.name, err
            );
        }
    }
}

pub fn arp_reply_arrives(netdev: &NetDevice, arp: &ArpIPToEthernet) {
    if netdev.ipdev.address != 0 {
        println!(
            "Added arp table entry by arp reply ({} => {})",
            print_ip_addr(arp.sender_ip_addr),
            print_mac_addr(arp.sender_hardware_addr)
        );
        add_arp_table_entry(netdev, arp.sender_ip_addr, arp.sender_hardware_addr);
    }
}

pub fn send_arp_request(netdev: &NetDevice, target_ip: u32) {
    println!(
        "Sending ARP request via {} for {:x}",
        netdev.name, target_ip
    );

    let req = ArpIPToEthernet {
        hardware_type: ARP_HTYPE_ETHERNET,
        protocol_type: ETHER_TYPE_IP,
        hardware_len: ETHERNET_ADDRESS_LEN,
        protocol_len: IP_ADDRESS_LEN,
        opcode: ARP_OPERATION_CODE_REQUEST,
        sender_hardware_addr: netdev.macaddr,
        sender_ip_addr: netdev.ipdev.address,
        target_hardware_addr: ETHERNET_ADDRESS_BROADCAST,
        target_ip_addr: target_ip,
    }
    .to_packet();

    if let Err(err) = ethernet_output(
        netdev,
        ETHERNET_ADDRESS_BROADCAST,
        &req,
        ETHER_TYPE_ARP,
    ) {
        eprintln!(
            "failed to send arp request on {}: {}",
            netdev.name, err
        );
    }
}
