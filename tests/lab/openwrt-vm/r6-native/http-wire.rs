//! Bounded HTTP wire client for the isolated r6 guest acceptance VM.
use std::{
    fs,
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    time::{Duration, Instant},
};

fn main() -> std::io::Result<()> {
    if fs::read("/etc/xkeenwrt-r6-native-lab")? != b"r6-native-v1\n"
        || !fs::read_to_string("/etc/openwrt_release")?
            .lines()
            .any(|line| line == "DISTRIB_RELEASE='25.12.6'")
    {
        return Err(std::io::Error::other("guest guard"));
    }
    let mut args = std::env::args().skip(1);
    let address = args
        .next()
        .ok_or_else(|| std::io::Error::other("missing address"))?
        .parse::<SocketAddr>()
        .map_err(|_| std::io::Error::other("invalid address"))?;
    let deadline_secs = args
        .next()
        .ok_or_else(|| std::io::Error::other("missing deadline"))?
        .parse::<u64>()
        .map_err(|_| std::io::Error::other("invalid deadline"))?;
    if !(1..=225).contains(&deadline_secs) || args.next().is_some() {
        return Err(std::io::Error::other("deadline or arguments out of range"));
    }
    let request = fs::read("/tmp/r6-native-request")?;
    if request.is_empty() || request.len() > 65_536 {
        return Err(std::io::Error::other("request size"));
    }
    let started = Instant::now();
    let deadline = started + Duration::from_secs(deadline_secs);
    let result = (|| -> std::io::Result<()> {
        let mut socket = TcpStream::connect_timeout(&address, Duration::from_secs(5))?;
        socket.set_write_timeout(Some(Duration::from_secs(5)))?;
        socket.write_all(&request)?;
        let mut response = Vec::new();
        let mut buffer = [0u8; 8192];
        loop {
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::TimedOut, "deadline"))?;
            socket.set_read_timeout(Some(remaining))?;
            match socket.read(&mut buffer) {
                Ok(0) => break,
                Ok(read) => {
                    if response.len() + read > 1_048_576 {
                        return Err(std::io::Error::other("response size"));
                    }
                    response.extend_from_slice(&buffer[..read]);
                }
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            }
        }
        fs::write("/tmp/r6-native-response", response)
    })();
    eprintln!("R6_NATIVE_HTTP_ELAPSED_MS={}", started.elapsed().as_millis());
    result
}
