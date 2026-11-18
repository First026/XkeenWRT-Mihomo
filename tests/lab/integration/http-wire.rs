//! Фиксированный HTTP-клиент для одноразового гостя; секреты не печатает.
use std::{
    fs,
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    time::{Duration, Instant},
};

fn main() -> std::io::Result<()> {
    let cmdline = fs::read_to_string("/proc/cmdline")?;
    let marker = fs::read("/etc/xkeenwrt-isolation-lab")?;
    let release = fs::read_to_string("/etc/openwrt_release")?;
    if !cmdline
        .split_ascii_whitespace()
        .any(|s| s == "xkeenwrt.isolation_lab=1")
        || marker != b"xkeenwrt-validator-lab-v1\n"
        || !release.lines().any(|s| s == "DISTRIB_RELEASE='25.12.6'")
    {
        return Err(std::io::Error::other("guest guard"));
    }
    let request = fs::read("/tmp/xkeenwrt-http-wire")?;
    if request.len() > 65536 {
        return Err(std::io::Error::other("request limit"));
    }
    let started = Instant::now();
    let deadline = started + Duration::from_secs(225);
    let result = (|| -> std::io::Result<()> {
        let addr: SocketAddr = "127.0.0.1:1000".parse().unwrap();
        let mut socket = TcpStream::connect_timeout(&addr, Duration::from_secs(5))?;
        socket.set_write_timeout(Some(Duration::from_secs(5)))?;
        socket.write_all(&request)?;
        let mut response = Vec::new();
        let mut buf = [0u8; 8192];
        loop {
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::TimedOut, "deadline"))?;
            socket.set_read_timeout(Some(remaining))?;
            match socket.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if response.len() + n > 1_048_576 {
                        return Err(std::io::Error::other("response limit"));
                    }
                    response.extend_from_slice(&buf[..n]);
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }
        fs::write("/tmp/xkeenwrt-response", response)
    })();
    println!("LAB_HTTP_ELAPSED_MS={}", started.elapsed().as_millis());
    result
}
