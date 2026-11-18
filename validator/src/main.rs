mod child;
mod guardian;
mod preflight;
// Fail-closed protocol front end. No core is executed without the independently
// supervised, verified sandbox described in the isolation decision.
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::Deserialize;
use std::collections::HashSet;
use std::io::{self, Write};
use std::time::{Duration, Instant};

const MAX_INPUT: usize = 18 * 1024 * 1024;
const MAX_CONFIG: usize = 1024 * 1024;
const MAX_ASSETS: usize = 8 * 1024 * 1024;
const MAX_FILES: usize = profile_policy::MAX_PROVIDER_FILES;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Request {
    version: u8,
    config: String,
    assets: Vec<Asset>,
    #[serde(default)]
    overlay: profile_policy::ManagedOverlay,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Asset {
    path: String,
    content_base64: String,
}

fn read_request() -> Result<Vec<u8>, &'static str> {
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut result = Vec::new();
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err("INPUT_TIMEOUT");
        }
        let mut fd = libc::pollfd {
            fd: libc::STDIN_FILENO,
            events: libc::POLLIN,
            revents: 0,
        };
        let n = unsafe {
            libc::poll(
                &mut fd,
                1,
                remaining.as_millis().max(1).min(i32::MAX as u128) as i32,
            )
        };
        if n < 0 {
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err("INPUT_ERROR");
        }
        if n == 0 {
            return Err("INPUT_TIMEOUT");
        }
        if fd.revents & (libc::POLLERR | libc::POLLNVAL) != 0 {
            return Err("INPUT_ERROR");
        }
        let mut buffer = [0u8; 8192];
        let n = unsafe { libc::read(libc::STDIN_FILENO, buffer.as_mut_ptr().cast(), buffer.len()) };
        if n == 0 {
            return Ok(result);
        }
        if n < 0 {
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err("INPUT_ERROR");
        }
        if result.len() + n as usize > MAX_INPUT {
            return Err("INPUT_TOO_LARGE");
        }
        result.extend_from_slice(&buffer[..n as usize]);
    }
}

fn valid_path(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= 1024
        && path.split('/').all(|part| {
            !part.is_empty()
                && part != "."
                && part != ".."
                && part.len() <= 255
                && part
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b'.'))
        })
}
fn valid_request(bytes: &[u8]) -> Option<Request> {
    let request = serde_json::from_slice::<Request>(bytes).ok()?;
    if request.version != 1 || request.config.len() > MAX_CONFIG || request.assets.len() > MAX_FILES
    {
        return None;
    }
    let mut paths = HashSet::new();
    let mut total = 0usize;
    for asset in &request.assets {
        if !valid_path(&asset.path) || asset.path == "config.yaml" || !paths.insert(&asset.path) {
            return None;
        }
        if asset.content_base64.len() > MAX_ASSETS.div_ceil(3) * 4 {
            return None;
        }
        let content = STANDARD.decode(&asset.content_base64).ok()?;
        total = total.checked_add(content.len())?;
        if total > MAX_ASSETS {
            return None;
        }
    }
    Some(request)
}
struct ChildFds {
    ready: i32,
    exec_error: i32,
    status: i32,
    core: i32,
}
fn main() {
    let args = std::env::args_os().skip(1).collect::<Vec<_>>();
    let marked = preflight::marked_guest();
    if !args.is_empty() {
        let (status, code) = if args.len() == 1 && args[0] == "--cleanup" && marked {
            match guardian::acquire() {
                Ok(_lock) if guardian::cleanup_only() => ("clean", "CLEANUP_COMPLETE"),
                Ok(_) => ("unavailable", "CLEANUP_FAILED"),
                Err(code) => ("unavailable", code),
            }
        } else {
            ("unavailable", "SANDBOX_UNAVAILABLE")
        };
        let _ = writeln!(
            io::stdout().lock(),
            "{{\"status\":\"{status}\",\"code\":\"{code}\"}}"
        );
        std::process::exit(if status == "clean" { 0 } else { 1 });
    }
    let admission = if marked {
        guardian::acquire().map(Some)
    } else {
        Ok(None)
    };
    let (status, code) = match admission {
        Err(code) => ("unavailable", code),
        Ok(_lock) => match read_request() {
            Err(code) => ("unavailable", code),
            Ok(data) => match valid_request(&data) {
                None => ("invalid", "INVALID_REQUEST"),
                Some(request) if marked => guardian::run(&request, _lock.as_ref().unwrap()),
                Some(_) => ("unavailable", "SANDBOX_UNAVAILABLE"),
            },
        },
    };
    let _ = writeln!(
        io::stdout().lock(),
        "{{\"status\":\"{status}\",\"code\":\"{code}\"}}"
    );
}
