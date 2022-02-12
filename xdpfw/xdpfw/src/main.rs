use anyhow::Context;
use aya::{
    //    maps::perf::AsyncPerfEventArray,
    maps::perf::PerfEventArray,
    programs::{Xdp, XdpFlags},
    util::online_cpus,
    Bpf,
};
use bytes::BytesMut;
use std::{
    convert::{TryFrom, TryInto},
    env, fs, net,
};
use tokio::{signal, task};

use xdpfw_common::PacketLog;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let path = match env::args().nth(1) {
        Some(path) => path,
        None => panic!("no path provided"),
    };
    let iface = match env::args().nth(2) {
        Some(iface) => iface,
        None => "eth0".to_string(),
    };

    let data = fs::read(path)?;
    let mut bpf = Bpf::load(&data)?;

    let probe: &mut Xdp = bpf.program_mut("xdpfw").unwrap().try_into()?;
    probe.load()?;
    //    probe.attach(&iface, XdpFlags::default())
    probe.attach(&iface, XdpFlags::SKB_MODE)
        .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;

    let mut perf_array = PerfEventArray::try_from(bpf.map_mut("EVENTS")?)?;

    for cpu_id in online_cpus()? {
        let mut buf = perf_array.open(cpu_id, None)?;

        task::spawn(async move {
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(1024))
                .collect::<Vec<_>>();

            loop {
                //let events = buf.read_events(&mut buffers).await.unwrap();
                let events = buf.read_events(&mut buffers).unwrap();
                for i in 0..events.read {
                    let buf = &mut buffers[i];
                    let ptr = buf.as_ptr() as *const PacketLog;
                    let data = unsafe { ptr.read_unaligned() };
                    let src_addr = net::Ipv4Addr::from(data.ipv4_address);
                    println!(
                        "LOG: SRC({}), PACKETLN({}) ACTION({}) HASH({}) IPL({}) UDPDP({}) UDPLN({}) UDPCALC({}) scratch({}) pkt_cnt({}) buf[0]({})",
                        src_addr,
                        data.packet_len,
                        data.action,
                        data.hash,
                        data.ip_ihl,
                        data.udp_dest_port,
                        data.udp_payload_len,
                        data.udp_payload_packet_calc,
                        data.scratch,
                        data.pkt_cnt,
                        data.buf[0],
                    );
                }
            }
        });
    }
    signal::ctrl_c().await.expect("failed to listen for event");
    Ok::<_, anyhow::Error>(())
}
