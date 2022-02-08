use std::net::{UdpSocket, SocketAddr};

fn main() -> std::io::Result<()> {
    println!("Hello, world!");

    //
    let socket = UdpSocket::bind("10.138.0.64:0")?;

    let addr = SocketAddr::from(([10, 138, 0, 64], 2345));

    let mut buf = [5; 999];

    for i in 0..1000 {
        socket.send_to(&buf, &addr)?;
        std::thread::sleep(std::time::Duration::from_millis(1_000));
        println!("sent pktno={}", i);
    }

    Ok(())
}
