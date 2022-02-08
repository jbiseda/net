use std::env;
use std::net::UdpSocket;


fn main() -> std::io::Result<()> {
    println!("Reading...");

    let args: Vec<String> = env::args().collect();

    let addr_string = &args[1];

    let socket = UdpSocket::bind(addr_string)?;

    for i in 0..1_000 {
        let mut buf = [0; 1500];
        let (amt, _src) = socket.recv_from(&mut buf)?;
        println!("pkt len={} cnt={}", amt, i);
    }
    
    Ok(())
}
