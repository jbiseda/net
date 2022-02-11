#![no_std]

#[repr(C)]
#[repr(packed)]
#[derive(Copy, Clone)]
pub struct PacketLog {
    pub ipv4_address: u32,
    pub action: u32,
    pub hash: u64,
    pub ip_ihl: u8,
    pub udp_dest_port: u16,
    pub udp_payload_len: usize,
    pub packet_len: usize,
    pub udp_payload_packet_calc: usize,
    pub scratch: u64,
    pub pkt_cnt: u64,
    pub buf: [u8; 64],
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for PacketLog {}
