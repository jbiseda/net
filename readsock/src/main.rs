use std::env;
use std::net::UdpSocket;


fn main() -> std::io::Result<()> {
    println!("Reading...");

    let args: Vec<String> = env::args().collect();

    let addr_string = &args[1];

    let socket = UdpSocket::bind(addr_string)?;

    let mut pkt_cnt = 0;
    loop {
        let mut buf = [0; 1500];
        let (amt, _src) = socket.recv_from(&mut buf)?;
        pkt_cnt += 1;
        println!("pkt len={} cnt={} buf[0]={}", amt, pkt_cnt, buf[0]);
    }
    
    Ok(())
}
