#[derive(Clone, Copy, Debug, Default)]
pub struct UdpHeader {
    pub src_port: u16,
    pub dest_port: u16,
    pub length: u16,
    pub checksum: u16,
}

#[derive(Clone, Debug, Default)]
pub struct TcpHeader {
    pub src_port: u16,
    pub dest_port: u16,
    pub seq: u32,
    pub ackseq: u32,
    pub offset: u8,
    pub tcpflag: u8,
    pub window: u16,
    pub checksum: u16,
    pub urg_pointer: u16,
    pub options: Vec<u8>,
    pub tcpdata: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct DummyHeader {
    pub src_addr: u32,
    pub dest_addr: u32,
    pub protocol: u16,
    pub length: u16,
}

fn be_u16(b: &[u8]) -> u16 { u16::from_be_bytes([b[0], b[1]]) }
fn be_u32(b: &[u8]) -> u32 { u32::from_be_bytes([b[0], b[1], b[2], b[3]]) }

impl DummyHeader {
    pub fn to_packet(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(12);
        b.extend_from_slice(&self.src_addr.to_be_bytes());
        b.extend_from_slice(&self.dest_addr.to_be_bytes());
        b.extend_from_slice(&self.protocol.to_be_bytes());
        b.extend_from_slice(&self.length.to_be_bytes());
        b
    }
}

impl UdpHeader {
    pub fn to_packet(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(8);
        b.extend_from_slice(&self.src_addr.to_be_bytes());
        b.extend_from_slice(&self.dest_addr.to_be_bytes());
        b.extend_from_slice(&self.protocol.to_be_bytes());
        b.extend_from_slice(&self.length.to_be_bytes());
        b
    }

    pub fn parse_packet(packet: &[u8]) -> UdpHeader {
        UdpHeader {
            src_addr: be_u16(&packet[0..2]),
            dest_addr: be_u16(&packet[2..4]),
            length: be_u16(&packet[4..6]),
            checksum: be_u16(&packet[6..8]),
        }
    }
}

impl TcpHeader {
    pub fn to_packet(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(20 + self.options.len() + self.tcpdata.len());
        b.extend_from_slice(&self.src_addr.to_be_bytes());
        b.extend_from_slice(&self.dest_addr.to_be_bytes());
        b.extend_from_slice(&self.seq.to_be_bytes());
        b.extend_from_slice(&self.ackseq.to_be_bytes());
        b.extend_from_slice(&self.offset);
        b.extend_from_slice(&self.tcpflag);
        b.extend_from_slice(&self.window.to_be_bytes());
        b.extend_from_slice(&self.checksum.to_be_bytes());
        b.extend_from_slice(&self.urg_pointer.to_be_bytes());

        if !self.options.is_empty() {
            b.extend_from_slice(&self.options);
        }
        if !self.tcpdata.is_empty() {
            b.extend_from_slice(&self.tcpdata);
        }
        b
    }

    pub fn parse_packet(packet: &[u8]) -> TcpHeader {
        let mut header = TcpHeader {
            src_addr: be_u16(&packet[0..2]),
            dest_addr: be_u16(&packet[2..4]),
            seq: be_u32(&packet[4..8]),
            ackseq: be_u32(&packet[8..12]),
            offset: packet[12],
            tcpflag: [13],
            window: be_u16(&packet[14..16]),
            checksum: be_u16(&packet[16..18]),
            urg_pointer: be_u16(&packet[18..20]),
            options: Vec::new(),
            tcpdata: Vec::new(),
        };

        let header_len = (header.offset >> 2) as usize;

        if 20 < header_len && header_len <= packet.len() {
            header.options = packet[20..header_len].to_vec();
        }
        if header_len < packet.len() {
            header.tcpdata = packet[header_len..].to_vec();
        }
    }
}