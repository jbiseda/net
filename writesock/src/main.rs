use std::env;
use std::net::{UdpSocket, SocketAddr};

fn main() -> std::io::Result<()> {

    let args: Vec<String> = env::args().collect();

    let addr_string = &args[1];

    println!("Sending...");

    let socket = UdpSocket::bind("0.0.0.0:0")?;

    let addr: SocketAddr = addr_string.parse().unwrap();

    let buf = [5; 999];

    for i in 0..1000 {
        socket.send_to(&buf, &addr)?;
        std::thread::sleep(std::time::Duration::from_millis(1_000));
        println!("sent pktno={}", i);
    }

    Ok(())
}
