use std::{net::SocketAddr, path::Path};
use xkeen_ui::{
    http::{AuthState, TrustedApps},
    management::{self, ManagementBoundary},
    runtime::{
        RuntimeCommand,
        ipc::{self, RuntimeClient},
    },
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [cmd] if cmd == "package-version" => {
            let version = option_env!("XKEENWRT_PACKAGE_VERSION").ok_or("package version is not embedded")?;
            if version.is_empty()
                || version.len() > 128
                || !version
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._+-".contains(&b))
            {
                return Err("invalid embedded package version".into());
            }
            println!("{version}");
            return Ok(());
        }
        [cmd] if cmd == "package-check" => {
            return if xkeen_ui::platform::Platform::compatible_packages() {
                Ok(())
            } else {
                Err("package integrity check failed".into())
            };
        }
        [cmd] if cmd == "runtime" => return ipc::serve().map_err(Into::into),
        [cmd, nonce] if cmd == "core-run" => {
            return xkeen_ui::runtime::grant::exec(nonce).map_err(|_| "core launch grant rejected".into());
        }
        _ => (),
    }
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(async_main(args))
}

async fn async_main(args: Vec<String>) -> Result<(), Box<dyn std::error::Error>> {
    match args.as_slice() {
        [cmd] if cmd == "serve" => {
            if xkeen_ui::platform::Platform::inspect().platform != "openwrt" {
                return Err("serve requires OpenWrt".into());
            }
            if unsafe { nix::libc::geteuid() } != 0 {
                return Err("serve requires root".into());
            }
            let dir = Path::new("/etc/xkeenwrt");
            use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
            match std::fs::DirBuilder::new().mode(0o700).create(dir) {
                Ok(()) => std::fs::File::open("/etc")?.sync_all()?,
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => (),
                Err(e) => return Err(e.into()),
            }
            let metadata = std::fs::symlink_metadata(dir)?;
            if !metadata.is_dir() || metadata.file_type().is_symlink() || metadata.uid() != 0 {
                return Err("unsafe configuration directory".into());
            }
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
            let profiles = dir.join("profiles");
            match std::fs::DirBuilder::new().mode(0o700).create(&profiles) {
                Ok(()) => std::fs::File::open(dir)?.sync_all()?,
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => (),
                Err(e) => return Err(e.into()),
            }
            let profile_metadata = std::fs::symlink_metadata(&profiles)?;
            if !profile_metadata.is_dir() || profile_metadata.file_type().is_symlink() || profile_metadata.uid() != 0 {
                return Err("unsafe profile directory".into());
            }
            std::fs::set_permissions(&profiles, std::fs::Permissions::from_mode(0o700))?;
            let boundary = management::discover().unwrap_or_else(ManagementBoundary::loopback);
            let (listener, access, addr) = match boundary.bind_listener() {
                Ok(listener) => (listener, boundary.access, boundary.address),
                Err(_) => {
                    let fallback = ManagementBoundary::loopback();
                    let listener = fallback.bind_listener()?;
                    (listener, fallback.access, fallback.address)
                }
            };
            let apps = TrustedApps::new(profiles);
            let overlay = tokio::spawn(serve_tailscale(apps.clone()));
            let result = axum::serve(
                listener,
                apps.router(addr, access)
                    .into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await;
            overlay.abort();
            result?;
        }
        [cmd, flag, state, port_flag, port]
            if cmd == "preview" && flag == "--state-dir" && port_flag == "--port" && port == "18080" =>
        {
            if unsafe { nix::libc::geteuid() } == 0 {
                return Err("preview must run unprivileged".into());
            }
            let dir = Path::new(state);
            if !dir.is_absolute()
                || dir
                    .components()
                    .any(|c| matches!(c, std::path::Component::ParentDir | std::path::Component::CurDir))
            {
                return Err("preview state directory must be a clean absolute path".into());
            }
            use std::os::unix::fs::DirBuilderExt;
            match std::fs::DirBuilder::new().mode(0o700).create(dir) {
                Ok(()) => (),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    return Err("preview state directory already exists".into());
                }
                Err(e) => return Err(e.into()),
            }
            std::fs::File::open(dir.parent().ok_or("missing preview parent")?)?.sync_all()?;
            let token_path = dir.join("bootstrap-token");
            let token = xkeen_ui::private_file::load_or_create_bootstrap(&token_path)?;
            std::fs::DirBuilder::new().mode(0o700).create(dir.join("profiles"))?;
            std::fs::File::open(dir)?.sync_all()?;
            let addr: SocketAddr = "127.0.0.1:18080".parse()?;
            let auth = AuthState::new(token, dir.join("password-hash"))?;
            let listener = tokio::net::TcpListener::bind(addr).await?;
            println!("Offline preview bootstrap token file: {}", token_path.display());
            axum::serve(
                listener,
                xkeen_ui::http::app_with_profiles(auth, addr, dir.join("profiles"))
                    .into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await?;
        }
        [cmd, action] if cmd == "ctl" => {
            let cmd = match action.as_str() {
                "status" => RuntimeCommand::Status,
                "enable" => RuntimeCommand::Enable,
                "disable" => RuntimeCommand::Disable,
                "reload" => RuntimeCommand::Reload,
                _ => return Err("unknown control command".into()),
            };
            let reply = RuntimeClient::command(cmd)?;
            println!("{}", serde_json::to_string(&reply)?);
            if reply.code != "OK" {
                std::process::exit(1);
            }
        }
        _ => return Err("usage: xkeenwrt-ui serve|runtime|ctl <status|enable|disable|reload>".into()),
    }
    Ok(())
}

async fn serve_tailscale(apps: TrustedApps) {
    let mut current: Option<(ManagementBoundary, tokio::task::JoinHandle<()>)> = None;
    let mut timer = tokio::time::interval(std::time::Duration::from_secs(5));
    loop {
        timer.tick().await;
        let wanted = management::discover_tailscale();
        if current
            .as_ref()
            .is_some_and(|(b, t)| Some(b) != wanted.as_ref() || t.is_finished())
            && let Some((_, task)) = current.take()
        {
            task.abort();
        }
        if current.is_none()
            && let Some(boundary) = wanted
            && let Ok(listener) = boundary.bind_listener()
        {
            let router = apps.router(boundary.address, boundary.access.clone());
            let task = tokio::spawn(async move {
                let _ = axum::serve(listener, router.into_make_service_with_connect_info::<SocketAddr>()).await;
            });
            current = Some((boundary, task));
        }
    }
}
