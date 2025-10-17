use std::fmt::Write as _;

pub const ICMP_TYPE_ECHO_REPLY: u8 = 0;
pub const ICMP_TYPE_DESTINATION_UNREACHABLE: u8 = 3;
pub const ICMP_TYPE_ECHO_REQUEST: u8 = 8;
pub const ICMP_TYPE_TIME_EXCEEDED: u8 = 11;

pub const IP_PROTOCOL_NUM_ICMP: u8 = 1;

#[derive(Clone, Debug)]
pub struct NetDevice {
    pub name: String,
}

fn ip_packet_encapsulate_output(
    _dev: &NetDevice,
    _src: u32,
    _dst: u32,
    _payload: &[u8],
    _protocol: u8,
){
    //ここでIPヘッダをつけて送信
}

//型定義
#[derive(Clone, Copy, Debug)]
pub struct IcmpHeader {
    pub icmp_type: u8,
    pub icmp_code: u8,
    pub checksum: u16,
}

#[derive(Clone, Debug)]
pub struct IcmpEcho {
    pub identify: u16,
    pub sequence: u16,
    pub timestamp: [u8; 8],
    pub data: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct IcmpDestinationUnreachable {
    pub unused: u32,
    pub data: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct IcmpTimeExceeded {
    pub unused: u32,
    pub data: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct IcmpMessage {
    pub icmp_header: IcmpHeader,
    pub icmp_echo: Option<IcmpEcho>,
    pub icmp_destination_unreachable: Option<IcmpDestinationUnreachable>,
    pub icmp_time_exceeded: Option<IcmpTimeExceeded>,
}

fn u16_be(b: &[u8]) -> u16 {
    let mut a = [0u8; 2];
    a.copy_from_slice(&b[0..2]);
    u16::from_be_bytes(a)
}

fn u32_be(b: &[u8]) -> u32 {
    let mut a = [0u8; 4];
    a.copy_from_slice(&b[0..4]);
    u32::from_be_bytes(a)
}

//Internet Checksum (RFC 1071)
fn calc_checksum(buf: &[u8]) -> [u8; 2] {
    let mut sum: u32 = 0;
    
    let mut i = 0;
    while i + 1 < buf.len() {
        let word = ((buf[i] as u16) << 8) | (buf[i +1] as u16);
        sum += word as u32;
        i += 2;
    }
    if i < buf.len() {
        sum += (buf[i] as u32) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    let checksum = !(sum as u16);
    checksum.to_be_bytes()
}

fn print_bytes_hex(data: &[u8]) -> String {
    let mut s = String::new();
    for b in data {
        let _ = write!(&mut s, "{:02x}", b);
    }
    s
}

impl IcmpMessage {
    pub fn reply_packet(&self) -> Vec<u8> {
        let echo = match & self.icmp_echo {
            Some(e) => e,
            None => return Vec::new(),
        };

        let mut b =Vec::with_capacity(8 + 8 + echo.data.len());
        //ICMPヘッダ
        b.push(ICMP_TYPE_ECHO_REPLY); //type
        b.push(0x00); //code
        b.extend_from_slice(&[0x00, 0x00]); //checksum(後で計算)
        //ICMP Echo
        b.extend_from_slice(&echo.identify.to_be_bytes());
        b.extend_from_slice(&echo.sequence.to_be_bytes());
        b.extend_from_slice(&echo.timestamp);
        b.extend_from_slice(&echo.data);

        //checksum計算
        let checksum = calc_checksum(&b);
        b[2] = checksum[0];
        b[3] = checksum[1];

        println!("Send ICMP Packet is {}", print_bytes_hex(&b));
        b
    }

    pub fn parse_packet(icmp_packet: &[u8]) -> Option<IcmpMessage> {
        if icmp_packet.len() < 4 {
            return None;
        }
        let hdr = IcmpHeader {
            icmp_type: icmp_packet[0],
            icmp_code: icmp_packet[1],
            checksum: u16_be(&icmp_packet[2..4]),
        };
        match hdr.icmp_type {
            ICMP_TYPE_ECHO_REQUEST | ICMP_TYPE_ECHO_REPLY => {
                if icmp_packet.len() < 16 {
                    return None;
                }
                let identify = u16_be(&icmp_packet[4..6]);
                let sequence = u16_be(&icmp_packet[6..8]);
                let mut timestamp = [0u8; 8];
                timestamp.copy_from_slice(&icmp_packet[8..16]);
                let data = icmp_packet[16..].to_vec();

                Some(IcmpMessage {
                    icmp_header: hdr,
                    icmp_echo: Some(IcmpEcho {
                        identify,
                        sequence,
                        timestamp,
                        data,
                    }),
                    icmp_destination_unreachable: None,
                    icmp_time_exceeded: None,
                })
            }
            ICMP_TYPE_DESTINATION_UNREACHABLE => {
                if icmp_packet.len() < 8 {
                    return None;
                }
                let unused = u32_be(&icmp_packet[4..8]);
                let data = icmp_packet[8..].to_vec();

                Some(IcmpMessage {
                    icmp_header: hdr,
                    icmp_echo: None,
                    icmp_destination_unreachable: Some(IcmpDestinationUnreachable {
                        unused,
                        data,
                    }),
                    icmp_time_exceeded: None,
                })
            }
            ICMP_TYPE_TIME_EXCEEDED => {
                if icmp_packet.len() < 8 {
                    return None;
                }
                let unused = u32_be(&icmp_packet[4..8]);
                let data = icmp_packet[8..].to_vec();

                Some(IcmpMessage {
                    icmp_header: hdr,
                    icmp_echo: None,
                    icmp_destination_unreachable: None,
                    icmp_time_exceeded: Some(IcmpTimeExceeded {
                        unused,
                        data,
                    }),
                })
            }
            _ => {
                Some(IcmpMessage {
                    icmp_header: hdr,
                    icmp_echo: None,
                    icmp_destination_unreachable: None,
                    icmp_time_exceeded: None,
                })
            }
        }
    }
}

//ICMP受信処理
pub fn icmp_input(inputdev: &NetDevice, source_addr: u32, dest_addr: u32, icmp_packet: &[u8]){
    if icmp_packet.len() < 4 {
        eprintln!("Received ICMP Packet is too short");
        return;
    }

    let Some(icmpmsg) = IcmpMessage::parse_packet(icmp_packet) else {
        eprintln!("Failed to parse ICMP Packet");
        return;
    };

    match icmpmsg.icmp_header.icmp_type {
        ICMP_TYPE_ECHO_REPLY => {
            println!("ICMP ECHO REPLY is received");
        }
        ICMP_TYPE_ECHO_REQUEST => {
            println!("ICMP ECHO REQUEST is received, Create Reply Packet");
            let reply = icmpmsg.reply_packet();
            if !reply.is_empty() {
                ip_packet_encapsulate_output(
                    inputdev,
                    source_addr,
                    dest_addr,
                    &reply,
                    IP_PROTOCOL_NUM_ICMP,
                );
            }
        }
        _ => {
            //必要なら他のタイプも処理
        }
    }
}
