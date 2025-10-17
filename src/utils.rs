pub fn sum_byte_arr(packet: &[u8]) -> u32 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < packet.len() {
        let w = u16::from_be_bytes([packet[i], packet[i + 1]]) as u32;
        sum = sum.wrapping_add(w);
        i += 2;
    }
    sum
}

pub fn calc_checksum(packet: &[u8]) -> [u8; 2] {
    let mut sum = sum_byte_arr(packet);
    sum = (sum & 0xFFFF) + (sum >> 16);
    let checksum = !(sum as u16);
    checksum.to_be_bytes()
}

pub fn print_mac_addr(mac: [u8; 6]) -> String {
    let mut s = String::new();
    for (i, b) in mac.iter().enumerate() {
        use std::fmt::Write;
        let _ = write!(&mut s, "{:x}", b);
        if i != 5 {
            s.push(':');
        }
    }
    s
}

pub fn byte_to_u16(b: &[u8]) -> u16 {
    u16::from_be_bytes(b[0], b[1])
}

pub fn byte_to_u32(b: &[u8]) -> u32 {
    u32::from_be_bytes(b[0], b[1], b[2], b[3])
}

pub fn u16_to_byte(i: u16) -> [u8; 2] {
    i.to_be_bytes()
}

pub fn u32_to_byte(i: u32) -> [u8; 4] {
    i.to_be_bytes()
}