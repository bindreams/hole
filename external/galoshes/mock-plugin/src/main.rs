use std::net::SocketAddr;

use tokio::io;
use tokio::net::{TcpListener, TcpStream};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let local_host = std::env::var("SS_LOCAL_HOST")?;
    let local_port: u16 = std::env::var("SS_LOCAL_PORT")?.parse()?;
    let remote_host = std::env::var("SS_REMOTE_HOST")?;
    let remote_port: u16 = std::env::var("SS_REMOTE_PORT")?.parse()?;

    let local_addr: SocketAddr = format!("{local_host}:{local_port}").parse()?;
    let remote_addr = format!("{remote_host}:{remote_port}");

    eprintln!("mock-plugin: listening on {local_addr}, forwarding to {remote_addr}");
    let listener = TcpListener::bind(local_addr).await?;

    loop {
        let (inbound, peer) = listener.accept().await?;
        eprintln!("mock-plugin: accepted connection from {peer}");
        let remote = remote_addr.clone();

        tokio::spawn(async move {
            match TcpStream::connect(&remote).await {
                Ok(outbound) => {
                    let (mut ri, mut wi) = io::split(inbound);
                    let (mut ro, mut wo) = io::split(outbound);

                    let c2s = io::copy(&mut ri, &mut wo);
                    let s2c = io::copy(&mut ro, &mut wi);

                    let _ = tokio::try_join!(c2s, s2c);
                }
                Err(e) => {
                    eprintln!("mock-plugin: failed to connect to {remote}: {e}");
                }
            }
        });
    }
}
