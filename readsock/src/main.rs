use std::net::UdpSocket;


fn main() -> std::io::Result<()> {
    println!("Hello, world!");

    let socket = UdpSocket::bind("10.138.0.64:2345")?;

    let mut pktcnt = 0;

    while true {
        let mut buf = [0; 1500];
        let (amt, src) = socket.recv_from(&mut buf)?;
        println!("pkt len={} cnt={}", amt, pktcnt);
        pktcnt += 1;
    }
    
    
    Ok(())
}
