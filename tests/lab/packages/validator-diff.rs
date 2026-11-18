//! Lab-only differential: direct validator vs the frozen production launcher.
use std::{fs::{self, File, OpenOptions}, io::{Read, Seek, SeekFrom, Write}, os::{fd::{AsRawFd, FromRawFd}, unix::fs::MetadataExt}, process::{Command, Stdio}, thread, time::{Duration, Instant}};
use sha2::{Digest, Sha256};
use xkeenwrt_recovery::{RuntimeIncarnationIdentity, VerifiedPurpose, run_verified_fd_in_cgroup, runtime_incarnation_path};
const VALIDATOR: &str = "/usr/libexec/xkeenwrt/xkeenwrt-validate";
const REQUEST: &str = "/usr/share/xkeen-lab-diagnostic/request.json";
const PIN: &str = "ce3907df464cdb3219f6938b0acc47593cd642cfa932ebb672d712c1b67e416f";
fn memfd(name: &std::ffi::CStr) -> std::io::Result<File> {
    let fd = unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC) };
    if fd < 0 { return Err(std::io::Error::last_os_error()); }
    Ok(unsafe { File::from_raw_fd(fd) })
}
fn bounded_child(mut c: std::process::Child, timeout: Duration) -> std::io::Result<Option<std::process::ExitStatus>> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = c.try_wait()? { return Ok(Some(status)); }
        if Instant::now() >= deadline {
            // An unreaped Child retains its PID; no external shell watchdog is used.
            let _ = c.kill();
            let until = Instant::now() + Duration::from_secs(3);
            while Instant::now() < until { if c.try_wait()?.is_some() { break; } thread::sleep(Duration::from_millis(20)); }
            return Ok(None);
        }
        thread::sleep(Duration::from_millis(20));
    }
}
fn classify(file: &mut File) -> &'static str {
    if file.seek(SeekFrom::Start(0)).is_err() { return "OUTPUT_IO"; }
    let mut bytes = Vec::new();
    if file.take(4097).read_to_end(&mut bytes).is_err() || bytes.len() > 4096 { return "OUTPUT_LIMIT"; }
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(&bytes) else { return "INVALID_OUTPUT"; };
    match (v.get("status").and_then(|x| x.as_str()), v.get("code").and_then(|x| x.as_str())) {
        (Some("clean"), Some("CLEANUP_COMPLETE")) => "CLEANUP_COMPLETE",
        (Some("valid"), Some("VALID")) => "VALID",
        (Some("invalid"), Some("INVALID_REQUEST")) => "INVALID_REQUEST",
        (Some("invalid"), Some("INVALID_CONFIG")) => "INVALID_CONFIG",
        (Some("unavailable"), Some("SANDBOX_UNAVAILABLE")) => "SANDBOX_UNAVAILABLE",
        (Some("unavailable"), Some("CORE_UNAVAILABLE")) => "CORE_UNAVAILABLE",
        (Some("unavailable"), Some("WORKER_FAILED")) => "WORKER_FAILED",
        (Some("unavailable"), Some("ASSETS_UNVERIFIED")) => "ASSETS_UNVERIFIED",
        (Some("unavailable"), Some("BUSY")) => "BUSY",
        _ => "OTHER",
    }
}
fn pinned() -> std::io::Result<File> {
    let mut f = OpenOptions::new().read(true).open(VALIDATOR)?;
    let m = f.metadata()?;
    if !m.is_file() || m.uid() != 0 || m.nlink() != 1 || m.mode() & 0o022 != 0 { return Err(std::io::Error::other("metadata")); }
    let mut h = Sha256::new(); let mut b = [0; 65536];
    loop { let n=f.read(&mut b)?; if n==0 { break; } h.update(&b[..n]); }
    if h.finalize().iter().map(|b| format!("{b:02x}")).collect::<String>() != PIN { return Err(std::io::Error::other("hash")); }
    f.seek(SeekFrom::Start(0))?; Ok(f)
}
fn input(bytes: &[u8]) -> std::io::Result<File> { let mut f=memfd(c"diag-in")?; f.write_all(bytes)?; f.seek(SeekFrom::Start(0))?; Ok(f) }
fn direct(label: &str, args: &[&str], request: &[u8], timeout: Duration) -> std::io::Result<()> {
    let input=input(request)?; let mut output=memfd(c"diag-out")?;
    let child=Command::new(VALIDATOR).args(args).stdin(Stdio::from(input)).stdout(Stdio::from(output.try_clone()?)).stderr(Stdio::null()).spawn()?;
    let status=bounded_child(child, timeout)?;
    println!("DIAG_{}_EXIT={}",label, match status { Some(s) if s.success()=>"ZERO",Some(_)=>"NONZERO",None=>"TIMEOUT" });
    println!("DIAG_{}_RESULT={}",label,classify(&mut output)); Ok(())
}
fn fd_run(label:&str, executable:&File, cgroup:&File, args:&[String], request:&[u8], purpose:VerifiedPurpose, timeout:Duration) -> std::io::Result<()> {
    let input=input(request)?; let mut output=memfd(c"diag-out")?; let null=OpenOptions::new().read(true).write(true).open("/dev/null")?;
    let result=run_verified_fd_in_cgroup(executable.as_raw_fd(),args,cgroup.as_raw_fd(),input.as_raw_fd(),output.as_raw_fd(),null.as_raw_fd(),purpose,timeout);
    match result { Ok(true)=>println!("DIAG_{}_LAUNCH=ZERO",label), Ok(false)=>println!("DIAG_{}_LAUNCH=NONZERO",label), Err(e)=>println!("DIAG_{}_LAUNCH=ERRNO_{}",label,e.raw_os_error().unwrap_or(0)) }
    println!("DIAG_{}_RESULT={}",label,classify(&mut output)); Ok(())
}
fn worker(request:&[u8]) -> std::io::Result<()> {
    let id: RuntimeIncarnationIdentity = match fs::read("/var/run/xkeenwrt/incarnation.json").ok().and_then(|b| serde_json::from_slice(&b).ok()) {
        Some(id) => { println!("DIAG_FD_IDENTITY=OK"); id },
        None => { println!("DIAG_FD_IDENTITY=BAD"); return Ok(()); }
    };
    let cg = match runtime_incarnation_path(&id).and_then(File::open) {
        Ok(cg) => { println!("DIAG_FD_CGROUP=OK"); cg },
        Err(_) => { println!("DIAG_FD_CGROUP=BAD"); return Ok(()); }
    };
    let exe = match pinned() { Ok(exe) => { println!("DIAG_FD_PIN=OK"); exe }, Err(_) => { println!("DIAG_FD_PIN=BAD"); return Ok(()); } };
    fd_run("FD_CLEANUP",&exe,&cg,&["--cleanup".into()],&[],VerifiedPurpose::ValidatorCleanup,Duration::from_secs(25))?;
    fd_run("FD_PROTOCOL",&exe,&cg,&[],request,VerifiedPurpose::Validator,Duration::from_secs(75))
}
fn main() -> std::io::Result<()> {
    if !fs::read_to_string("/proc/cmdline")?.split_ascii_whitespace().any(|v| v=="xkeenwrt.isolation_lab=1") || fs::read("/etc/xkeenwrt-isolation-lab")? != b"xkeenwrt-validator-lab-v1\n" { println!("DIAG_GUARD=DENIED"); return Ok(()); }
    let request=fs::read(REQUEST)?;
    if request.len()>2048 || Sha256::digest(&request).iter().map(|b| format!("{b:02x}")).collect::<String>()!="a35fe44a46ff95bdf796d45b241260dc2d00fd74cd70e8f112d9cb116e26d0cd" { println!("DIAG_REQUEST=BAD"); return Ok(()); }
    if std::env::args().nth(1).as_deref()==Some("--fd-worker") { return worker(&request); }
    println!("DIAG_REQUEST=VERIFIED");
    if pinned().is_err() { println!("DIAG_VALIDATOR_PIN=BAD"); return Ok(()); }
    println!("DIAG_VALIDATOR_PIN=OK");
    if let Err(e) = direct("DIRECT_CLEANUP", &["--cleanup"], &[], Duration::from_secs(35)) { println!("DIAG_DIRECT_CLEANUP_ERROR=ERRNO_{}", e.raw_os_error().unwrap_or(0)); }
    if let Err(e) = direct("DIRECT_PROTOCOL", &[], &request, Duration::from_secs(85)) { println!("DIAG_DIRECT_PROTOCOL_ERROR=ERRNO_{}", e.raw_os_error().unwrap_or(0)); }
    let mut out=memfd(c"diag-fd-worker")?;
    let child=Command::new("/proc/self/exe").arg("--fd-worker").stdin(Stdio::null()).stdout(Stdio::from(out.try_clone()?)).stderr(Stdio::null()).spawn()?;
    let status=bounded_child(child, Duration::from_secs(110))?;
    println!("DIAG_FD_WORKER={}",match status {Some(s) if s.success()=>"ZERO",Some(_)=>"NONZERO",None=>"TIMEOUT"});
    out.seek(SeekFrom::Start(0))?; let mut text=String::new(); out.take(4097).read_to_string(&mut text)?;
    for line in text.lines() { if line.starts_with("DIAG_FD_") && line.len()<=100 && line.bytes().all(|b| b.is_ascii_uppercase()||b.is_ascii_digit()||b==b'_'||b==b'=') { println!("{line}"); } }
    Ok(())
}
