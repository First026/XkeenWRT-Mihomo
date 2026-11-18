//! Bounded cleanup for fixed child processes started in their own process group.
use std::{
    process::Child,
    time::{Duration, Instant},
};

pub(crate) fn terminate(child: &mut Child) -> bool {
    match child.try_wait() {
        Ok(Some(_)) => return true,
        Err(_) => return false,
        Ok(None) => (),
    }
    let pid = child.id();
    if let Ok(group) = i32::try_from(pid) {
        // Every caller creates a fresh process group whose ID is the child PID.
        unsafe {
            nix::libc::kill(-group, nix::libc::SIGKILL);
        }
    }
    let _ = child.kill();
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return true,
            Err(_) => return false,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(20)),
            Ok(None) => return false,
        }
    }
}
