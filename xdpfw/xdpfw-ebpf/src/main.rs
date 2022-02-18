#![no_std]
#![no_main]

use aya_bpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::{HashMap, PerfEventArray},
    programs::XdpContext,
};

mod bindings;
use bindings::{ethhdr, iphdr, udphdr};
//use bindings::{ethhdr, iphdr, ETH_P_IP, ETH_HDR_LEN};

//use std::hash::Hasher;
use core::hash::Hasher;
//use ahash::AHasher;

// if_ether.h
const ETH_P_IP: u16 = 0x0800;

// eth.h
const ETH_HDR_LEN: usize = 14;

const TCP_PROTO: u8 = 6;
const UDP_PROTO: u8 = 17;

use core::mem;
use memoffset::offset_of;

use xdpfw_common::PacketLog;

/*
#[map(name = "BLOCKLIST")]
static mut BLOCKLIST: HashMap<u32, u32> = HashMap::<u32, u32>::with_max_entries(1024, 0);
*/

#[map(name = "DUPTABLE")]
static mut DUPTABLE: HashMap<[u8; 32], u8> = HashMap::<[u8; 32], u8>::with_max_entries(1024, 0);

#[map(name = "EVENTS")]
static mut EVENTS: PerfEventArray<PacketLog> =
    PerfEventArray::<PacketLog>::with_max_entries(1024, 0);

#[xdp(name = "xdpfw")]
pub fn xdpfw(ctx: XdpContext) -> u32 {
    match unsafe { try_xdpfw(ctx) } {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

#[inline(always)]
unsafe fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

unsafe fn try_xdpfw(ctx: XdpContext) -> Result<u32, ()> {
    //let packet_len = ctx.data_end() - ctx.data();

    //if packet_len < 100 {
    //    return Ok(xdp_action::XDP_PASS);
    //}

    let h_proto = u16::from_be(unsafe { *ptr_at(&ctx, offset_of!(ethhdr, h_proto))? });
    if h_proto != ETH_P_IP {
        // we're only lookig at IPv4
        return Ok(xdp_action::XDP_PASS);
    }

    // ip proto
    let ip_proto =
        u8::from_be(unsafe { *ptr_at(&ctx, ETH_HDR_LEN + offset_of!(iphdr, protocol))? });
    if ip_proto != UDP_PROTO {
        // we only care about UDP
        return Ok(xdp_action::XDP_PASS);
    }

    let first_byte: u8 = *ptr_at(&ctx, ETH_HDR_LEN)?;
    let ip_ihl = first_byte & 0b00001111;
    let ip_header_len: usize = (ip_ihl as usize) * 4;

    let udp_dest_port = u16::from_be(unsafe {
        *ptr_at(&ctx, ETH_HDR_LEN + ip_header_len + offset_of!(udphdr, dest))?
    });
    if udp_dest_port == 2222 {
        return Ok(xdp_action::XDP_DROP);
    }

    return Ok(xdp_action::XDP_PASS);
}

unsafe fn try_xdpfw2(ctx: XdpContext) -> Result<u32, ()> {
    let packet_len = ctx.data_end() - ctx.data();

    if packet_len < 100 {
        return Ok(xdp_action::XDP_PASS);
    }

    let mut log_entry = PacketLog {
        ctx_data: ctx.data() as u64,
        ctx_data_end: ctx.data_end() as u64,
        ctx_diff: (ctx.data_end() - ctx.data()) as u64,
        ipv4_address: 0,
        action: xdp_action::XDP_PASS,
        hash: 0,
        ip_ihl: 0,
        tot_len: 0,
        udp_dest_port: 0,
        udp_payload_len: 0,
        packet_len: 0,
        udp_payload_packet_calc: 0,
        scratch: 0,
        buf: [0; 64],
        pkt_cnt: 0,
    };

    let h_proto = u16::from_be(unsafe { *ptr_at(&ctx, offset_of!(ethhdr, h_proto))? });
    if h_proto != ETH_P_IP {
        // we're only lookig at IPv4
        return Ok(xdp_action::XDP_PASS);
    }

    // ip proto
    let ip_proto =
        u8::from_be(unsafe { *ptr_at(&ctx, ETH_HDR_LEN + offset_of!(iphdr, protocol))? });
    if ip_proto != UDP_PROTO {
        // we only care about UDP
        return Ok(xdp_action::XDP_PASS);
    }

    let first_byte: u8 = *ptr_at(&ctx, ETH_HDR_LEN)?;
    /*
    // TODO do we want to sanity check this?
    let ip_version = (first_byte & 0b11110000) >> 4;
    if ip_version != 4 {
       // IPv4 version must always be 4
        return Ok(xdp_action::XDP_ABORT);
    }
    */
    let ip_ihl = first_byte & 0b00001111;
    let ip_header_len: usize = (ip_ihl as usize) * 4;
    log_entry.ip_ihl = ip_ihl;

    let tot_len =
        u16::from_be(unsafe { *ptr_at(&ctx, ETH_HDR_LEN + offset_of!(iphdr, tot_len))? });
    log_entry.tot_len = tot_len;

    let source = u32::from_be(unsafe { *ptr_at(&ctx, ETH_HDR_LEN + offset_of!(iphdr, saddr))? });
    log_entry.ipv4_address = source;

    let udp_dest_port = u16::from_be(unsafe {
        *ptr_at(&ctx, ETH_HDR_LEN + ip_header_len + offset_of!(udphdr, dest))?
    });
    log_entry.udp_dest_port = udp_dest_port;

    if udp_dest_port != 2222 {
        // only inspect specific port
        return Ok(xdp_action::XDP_PASS);
    }

    // len of udp header and data
    let udp_len: usize = u16::from_be(unsafe {
        *ptr_at(&ctx, ETH_HDR_LEN + ip_header_len + offset_of!(udphdr, len))?
    }) as usize;
    let udp_payload_len: usize = (udp_len as usize).saturating_sub(8);
    log_entry.udp_payload_len = udp_payload_len;

    log_entry.scratch = 3;
    unsafe {
        EVENTS.output(&ctx, &log_entry, 0);
    }

    return Ok(xdp_action::XDP_DROP);

    /*
    let slice = unsafe { core::slice::from_raw_parts::<u8>(ptr_at::<u8>(&ctx, ETH_HDR_LEN + ip_header_len + 8)?, 32) };
    log_entry.buf[..].clone_from_slice(&slice);
    */

    log_entry.scratch = 55;
    
    let offset: usize = ETH_HDR_LEN + ip_header_len + 8;

//    let udp_byte: u8 = u8::from_be(unsafe { *ptr_at::<u8>(&ctx, offset)? }) as u8;

    /*
    let udp_byte: u8 = u8::from_be(unsafe { *ptr_at::<u8>(&ctx, 42)? }) as u8;
    log_entry.buf[0] = udp_byte;
    */

    let udp_probe_byte: u8 = u8::from_be(unsafe { *ptr_at::<u8>(&ctx, 75)? });

    let udp_ptr: *const u8 = unsafe { ptr_at::<u8>(&ctx, 42)? };
    let slice = unsafe { core::slice::from_raw_parts::<u8>(udp_ptr, 32) };
    log_entry.buf[..32].clone_from_slice(&slice);


//    log_entry.scratch = udp_byte as u64;
    /*
    if ctx.data() + offset + 1 > ctx.data_end() {
        log_entry.scratch = 77;
    } else {
        let ptr: *const u8 = (ctx.data() + offset) as *const u8;
        log_entry.scratch = (*ptr) as u64;
    }
    */

    /*
    if ctx.data() + ETH_HDR_LEN + ip_header_len + 8 + 32 <= ctx.data_end() {
        log_entry.scratch = 66;
        let ptr: *const u8 = (ctx.data() + ETH_HDR_LEN + ip_header_len + 8) as *const u8;
        let slice = unsafe { core::slice::from_raw_parts::<u8>(ptr, 32) };
        log_entry.buf[..].clone_from_slice(&slice);
    }
    */

    unsafe {
        EVENTS.output(&ctx, &log_entry, 0);
    }


    // udp payload ptr
    /*
    let ptr: *const u8 = unsafe { ptr_at(&ctx, ETH_HDR_LEN + ip_header_len + 8)? };
    let slice = unsafe { core::slice::from_raw_parts::<u8>(ptr, 32) };
    log_entry.buf[..].clone_from_slice(&slice);
    */

//    let mut key = [0; 32];
//    key[..].copy_from_slice(&log_entry.buf[0..32]);



    /*
    match DUPTABLE.get(&key) {
        Some(val) => {
            log_entry.pkt_cnt = 555;
            log_entry.scratch = *val as u64;
            log_entry.ipv4_address = source;
            log_entry.action = xdp_action::XDP_DROP;
            //	    log_entry.hash = hash50;
            log_entry.ip_ihl = ip_ihl;
            log_entry.udp_dest_port = udp_dest_port;
            //	    log_entry.udp_payload_len = udp_payload_len;
            log_entry.packet_len = packet_len;
            //	    log_entry.udp_payload_packet_calc = udp_payload_packet_calc;
            unsafe {
                EVENTS.output(&ctx, &log_entry, 0);
            }
            return Ok(xdp_action::XDP_DROP);
        },
        None => (),
    }
    */
    //    DUPTABLE.insert(&key, &1, 0);

    let test_byte = u8::from_be(unsafe { *ptr_at(&ctx, 88)? });

    /*
    let mut hasher = FnvHasher::default();
    for i in 60..80 {
        let byte = u8::from_be(unsafe { *ptr_at(&ctx, ETH_HDR_LEN + i)? });
        let v = [byte; 1];
        hasher.write(&v[..]);
    }
    let hash50 = hasher.finish();
    */

    /*
    let ptr: *const u8 = unsafe { ptr_at(&ctx, ETH_HDR_LEN + 20 + 8)? };
    let slice = unsafe { core::slice::from_raw_parts::<u8>(ptr, 32) };
    */

    //    log_entry.buf[..].clone_from_slice(&slice);

    //let xoff = ETH_P_IP + 20 + 8;
    //memcpy();

    /*
        let mut hasher = FnvHasher::default();
        for i in 0..22 {
            let byte = u8::from_be(unsafe { *ptr_at(&ctx, ETH_HDR_LEN + i)? });
        let v = [byte; 1];
        hasher.write(&v[..]);
        }
        let hash = hasher.finish();
    */


    if udp_payload_len < 64 {
        return Ok(xdp_action::XDP_PASS); // ABORT?
    }

    /*
        let payload_off = ETH_HDR_LEN + ip_header_len + 8;
        if ctx.data().saturating_add(payload_off) >= ctx.data_end() {
           return Ok(xdp_action::XDP_ABORTED);
        }
        let verif_end_off = payload_off.saturating_add(64);
        if ctx.data().saturating_add(verif_end_off) >= ctx.data_end() {
           return Ok(xdp_action::XDP_ABORTED);
        }
    */

    /*
        let mut hasher = FnvHasher::default();
        for i in 0..2 {
            let byte = u8::from_be(unsafe { *ptr_at(&ctx, ETH_HDR_LEN + ip_header_len + 8 + i)? });
        let v = [byte; 1];
        hasher.write(&v[..]);
        }
        let hash = hasher.finish();
    */

    //    let first_payload_int = u32::from_be(unsafe { *ptr_at(&ctx, ETH_HDR_LEN + ip_header_len + udp_len)? });

    unsafe {
        let mut byte_ptr = ctx.data();

        byte_ptr += ETH_HDR_LEN;
        if byte_ptr > ctx.data_end() {
            return Err(());
        }

        byte_ptr += ip_header_len;
        if byte_ptr > ctx.data_end() {
            return Err(());
        }

        //	byte_ptr += udp_payload_len - 1;
        //	if byte_ptr > ctx.data_end() || byte_ptr < ctx.data() {
        //	    return Err(());
        //	}
    };

    //    let last_byte = u8::from_be( unsafe { *ptr_at(&ctx, ETH_HDR_LEN + ip_header_len + 8 + udp_payload_len - 1)? } );

    //    let ip = unsafe { ptr_at::<iphdr>(&ctx, ETH_HDR_LEN)? };
    // ip header length in 32-bit words
    //    let ihl = (*ip).ihl();
    //    let proto = (*ip).protocol();
    //    let source = (*ip).saddr().unwrap();

    //    let udp = unsafe { ptr_at::<udphdr>(&ctx, ETH_HDR_LEN + ((ihl as usize) * 4))? };
    //    let dport = (*udp).dest();
    //    let payload_len = (*udp).len();

    /*
        pub _bitfield_1: __BindgenBitfieldUnit<[u8; 1usize]>,

        pub fn ihl(&self) -> __u8 {
            unsafe { ::core::mem::transmute(self._bitfield_1.get(0usize, 4u8) as u8) }
        }
    */

    //    *ptr_at::<__BindgenBitfieldUnit<[u8; 1usize]>>(&ctx, ETH_HDR_LEN + offset_of!(iphdr, _bitfield_1))?;

    //    let _ihl = u8::from_be(unsafe { *ptr_at(&ctx, ETH_HDR_LEN + offset_of!(iphdr, ihl))? });


    //   let udp_ptr: *const u8 = unsafe { ptr_at::<u8>(&ctx, ETH_HDR_LEN + ip_header_len)? };
    //   let data_end_ptr: *const u8 = ctx.data_end() as *const u8;
    //   let raw_payload_len: usize = data_end_ptr - udp_ptr;

    let packet_len = ctx.data_end() - ctx.data();
    let eth_and_ip = ETH_HDR_LEN + ip_header_len;
    let udp_payload_packet_calc = packet_len - eth_and_ip - 8;

    /*
        let mut hasher = AHasher::new_with_keys(1234, 5678);
        hasher.write_u32(source);
        let _hash: u64 = hasher.finish();
    */

    let mut hasher = FnvHasher::default();
    //    hasher.write(&source.to_be_bytes());
    let ptr: *const u8 = unsafe { ptr_at::<u8>(&ctx, ETH_HDR_LEN + ip_header_len + 8)? };

    //    let slice = unsafe { core::slice::from_raw_parts(ptr, udp_payload_len) };
    let slice = unsafe { core::slice::from_raw_parts::<u8>(ptr, 1) };

    //    hasher.write(&slice);

    /*
    if (byte as usize).saturating_add(udp_payload_packet_calc) > ctx.data_end() {
        return Ok(xdp_action::XDP_ABORTED);
    }
    */

    let byte: *const u8 = unsafe { ptr_at(&ctx, ETH_HDR_LEN + ip_header_len + 8)? };
    //    let slice = unsafe { core::slice::from_raw_parts::<u8>(byte, udp_payload_packet_calc) };
    let slice = unsafe { core::slice::from_raw_parts::<u8>(byte, 1) };
    //    hasher.write(&slice);

    let byte: *const u8 = unsafe { ptr_at(&ctx, ETH_HDR_LEN + ip_header_len + 8 + 1)? };
    let slice = unsafe { core::slice::from_raw_parts::<u8>(byte, 1) };
    //    hasher.write(&slice);

    //    let hash: u64 = hasher.finish();


    log_entry.scratch = 123;
    log_entry.ipv4_address = source;
    log_entry.action = xdp_action::XDP_PASS;
    log_entry.hash = 765; //hash50;
    log_entry.ip_ihl = ip_ihl;
    log_entry.udp_dest_port = udp_dest_port;
    log_entry.udp_payload_len = udp_payload_len;
    log_entry.packet_len = packet_len;
    log_entry.udp_payload_packet_calc = udp_payload_packet_calc;

    unsafe {
        EVENTS.output(&ctx, &log_entry, 0);
    }

    Ok(xdp_action::XDP_PASS)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

///////////////////////////////////////////////////////////////
// https://github.com/servo/rust-fnv/blob/master/lib.rs
///////////////////////////////////////////////////////////////

#[allow(missing_copy_implementations)]
pub struct FnvHasher(u64);

impl Default for FnvHasher {
    #[inline]
    fn default() -> FnvHasher {
        FnvHasher(0xcbf29ce484222325)
    }
}

impl FnvHasher {
    /// Create an FNV hasher starting with a state corresponding
    /// to the hash `key`.
    #[inline]
    pub fn with_key(key: u64) -> FnvHasher {
        FnvHasher(key)
    }
}

impl Hasher for FnvHasher {
    #[inline]
    fn finish(&self) -> u64 {
        self.0
    }

    #[inline]
    fn write(&mut self, bytes: &[u8]) {
        let FnvHasher(mut hash) = *self;

        for byte in bytes.iter() {
            hash = hash ^ (*byte as u64);
            hash = hash.wrapping_mul(0x100000001b3);
        }

        *self = FnvHasher(hash);
    }
}

///////////////////////////////////////////////////////////////
