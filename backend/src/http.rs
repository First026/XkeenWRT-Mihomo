mod snapshot;
use crate::configuration::ConfigStore;
use crate::platform::Platform;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use axum::extract::Query;
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Path, Request, State},
    http::{HeaderMap, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::Deserialize;
use std::{
    collections::{HashMap, VecDeque},
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use uuid::Uuid;

const MAX_LOGIN_ATTEMPTS: u32 = 5;
const LOGIN_LOCKOUT: Duration = Duration::from_secs(60);
const MAX_TRACKED_LOGIN_IPS: usize = 4096;
const MAX_GLOBAL_LOGIN_ATTEMPTS: usize = 24;
const MAX_LOGIN_HASHES_IN_FLIGHT: usize = 2;

#[derive(Clone)]
pub struct AuthState {
    inner: Arc<Mutex<Auth>>,
    path: Option<PathBuf>,
    bootstrap_path: Option<PathBuf>,
}
struct Auth {
    bootstrap: Option<String>,
    password: Option<String>,
    sessions: HashMap<String, Instant>,
    setup_failures: Vec<Instant>,
    login_attempts: HashMap<IpAddr, (u32, Instant)>,
    global_login_attempts: VecDeque<Instant>,
}
impl AuthState {
    /// `bootstrap` must come from a root-only local file. Password persistence is
    /// fail-closed: no session is issued until the password is saved.
    pub fn new(bootstrap: String, path: PathBuf) -> std::io::Result<Self> {
        let password = match read_private_file(&path) {
            Ok(s) => {
                let parsed = PasswordHash::new(&s).map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "invalid password hash; local recovery required",
                    )
                })?;
                if parsed.algorithm.as_str() != "argon2id" || parsed.salt.is_none() || parsed.hash.is_none() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "invalid password hash; local recovery required",
                    ));
                }
                Some(s)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(e),
        };
        Ok(Self {
            inner: Arc::new(Mutex::new(Auth {
                bootstrap: if password.is_some() { None } else { Some(bootstrap) },
                password,
                sessions: HashMap::new(),
                setup_failures: Vec::new(),
                login_attempts: HashMap::new(),
                global_login_attempts: VecDeque::new(),
            })),
            bootstrap_path: path.parent().map(|p| p.join("bootstrap-token")),
            path: Some(path),
        })
    }
    fn trusted() -> Self {
        Self {
            inner: Arc::new(Mutex::new(Auth {
                bootstrap: None,
                password: None,
                sessions: HashMap::new(),
                setup_failures: Vec::new(),
                login_attempts: HashMap::new(),
                global_login_attempts: VecDeque::new(),
            })),
            path: None,
            bootstrap_path: None,
        }
    }
    #[doc(hidden)]
    pub fn for_test(token: &str) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Auth {
                bootstrap: Some(token.into()),
                password: None,
                sessions: HashMap::new(),
                setup_failures: Vec::new(),
                login_attempts: HashMap::new(),
                global_login_attempts: VecDeque::new(),
            })),
            path: None,
            bootstrap_path: None,
        }
    }
}
fn read_private_file(path: &std::path::Path) -> std::io::Result<String> {
    use std::{
        io::Read,
        os::unix::fs::{MetadataExt, OpenOptionsExt},
    };
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
        .open(path)?;
    let meta = file.metadata()?;
    if !meta.is_file()
        || meta.uid() != unsafe { nix::libc::geteuid() }
        || meta.mode() & 0o077 != 0
        || meta.nlink() != 1
        || meta.len() > 4096
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "auth file must be private and owned by the service user",
        ));
    }
    let mut result = String::new();
    file.read_to_string(&mut result)?;
    Ok(result)
}
#[derive(Clone)]
struct App {
    auth: AuthState,
    authority: String,
    profiles: PathBuf,
    preview: bool,
    trusted_access: Option<crate::management::TrustedAccess>,
    core_updates: Arc<crate::core_update::Manager>,
    self_update: Arc<crate::self_update::Updater>,
    preparation_capacity: Arc<tokio::sync::Semaphore>,
    runtime_capacity: Arc<tokio::sync::Semaphore>,
    status_snapshot: Arc<snapshot::StatusSnapshot>,
    relay_capacity: Arc<tokio::sync::Semaphore>,
    websocket_capacity: Arc<tokio::sync::Semaphore>,
    login_capacity: Arc<tokio::sync::Semaphore>,
}
#[derive(Deserialize)]
struct Credentials {
    password: String,
    #[serde(default)]
    token: String,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LoginReservation {
    Accepted(u32),
    Limited,
}
fn reserve_login_attempt(
    attempts: &mut HashMap<IpAddr, (u32, Instant)>, global_attempts: &mut VecDeque<Instant>, ip: IpAddr, now: Instant,
) -> LoginReservation {
    global_attempts.retain(|attempt| now.saturating_duration_since(*attempt) < LOGIN_LOCKOUT);
    if global_attempts.len() >= MAX_GLOBAL_LOGIN_ATTEMPTS {
        return LoginReservation::Limited;
    }
    attempts.retain(|_, (_, last)| now.saturating_duration_since(*last) < LOGIN_LOCKOUT * 2);
    if let Some((count, last)) = attempts.get_mut(&ip) {
        if now.saturating_duration_since(*last) > LOGIN_LOCKOUT {
            *count = 0;
        }
        if *count >= MAX_LOGIN_ATTEMPTS {
            return LoginReservation::Limited;
        }
        *count += 1;
        *last = now;
        global_attempts.push_back(now);
        return LoginReservation::Accepted(*count);
    }
    if attempts.len() >= MAX_TRACKED_LOGIN_IPS {
        return LoginReservation::Limited;
    }
    attempts.insert(ip, (1, now));
    global_attempts.push_back(now);
    LoginReservation::Accepted(1)
}
fn cookie(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .find_map(|s| s.trim().strip_prefix("session_id="))
}
async fn guard(State(app): State<App>, req: Request, next: Next) -> Response {
    let headers = req.headers();
    if headers.get(header::HOST).and_then(|v| v.to_str().ok()) != Some(app.authority.as_str()) {
        return result(StatusCode::FORBIDDEN, "FORBIDDEN");
    }
    if let Some(origin) = headers.get(header::ORIGIN)
        && origin.to_str().ok() != Some(format!("http://{}", app.authority).as_str())
    {
        return result(StatusCode::FORBIDDEN, "FORBIDDEN");
    }
    let path = req.uri().path();
    if path.starts_with("/ws/") && !headers.contains_key(header::ORIGIN) {
        return result(StatusCode::FORBIDDEN, "FORBIDDEN");
    }
    if let Some(policy) = &app.trusted_access {
        let Some(peer) = req.extensions().get::<axum::extract::ConnectInfo<SocketAddr>>() else {
            return result(StatusCode::FORBIDDEN, "FORBIDDEN");
        };
        if !policy.allows(peer.0.ip()) {
            return result(StatusCode::FORBIDDEN, "FORBIDDEN");
        }
    }
    if (path.starts_with("/api/") || path.starts_with("/ws/") || path.starts_with("/clash"))
        && path != "/api/auth/setup"
        && path != "/api/auth/login"
    {
        let authenticated = app.trusted_access.is_some()
            || cookie(headers).is_some_and(|id| {
                app.auth
                    .inner
                    .lock()
                    .unwrap()
                    .sessions
                    .get(id)
                    .is_some_and(|expires| *expires > Instant::now())
            });
        if !authenticated {
            return result(StatusCode::UNAUTHORIZED, "UNAUTHORIZED");
        }
    }
    let is_api = path.starts_with("/api/");
    let mut response = next.run(req).await;
    if is_api {
        response
            .headers_mut()
            .insert(header::CACHE_CONTROL, axum::http::HeaderValue::from_static("no-store"));
    }
    response
}
fn result(code: StatusCode, message: &str) -> Response {
    let description = match message {
        "UNAUTHORIZED" => "Authentication required",
        "FORBIDDEN" => "Host or origin is not allowed",
        "INVALID_BOOTSTRAP" => "Bootstrap token is invalid or setup is already complete",
        "INVALID_PASSWORD" => "Password does not meet the allowed length",
        "INVALID_CREDENTIALS" => "Invalid credentials",
        "RATE_LIMITED" => "Too many attempts; try again later",
        "NOT_READY" => "This operation is not ready",
        "UNSUPPORTED" => "This operation is unsupported",
        "BUSY" => "Profile storage is busy; retry shortly",
        "INSUFFICIENT_SPACE" => "Not enough free space to preserve the required storage reserve",
        "COMMIT_UNCERTAIN" => "Save outcome is uncertain; read the profile again before retrying",
        "PACKAGE_MISMATCH" => "Installed UI and core packages do not match this build",
        "RESCUE_NOT_READY" => "Persistent recovery is unavailable or incompatible",
        "CONFLICT" => "Profile changed; read the latest revision",
        "AUTH_STORAGE_ERROR" => "Authentication could not be saved; check local storage and restart",
        "GATEWAY_RUNNING" => "Перед обновлением нажмите «Остановить»",
        "UPDATE_RUNNING" => "Обновление XkeenWRT уже идёт",
        "NOT_NEWER" => "Можно выбрать только версию новее установленной",
        "UNKNOWN_RELEASE" => "Такого релиза XkeenWRT нет на GitHub",
        "INSTALLER_INVALID" => "Установщик релиза не прошёл проверку",
        "GITHUB_UNAVAILABLE" => "GitHub недоступен с роутера",
        "UPDATE_LAUNCH_FAILED" => "Не удалось запустить установщик",
        _ => message,
    };
    (
        code,
        Json(serde_json::json!({"success":false,"code":message,"error":description})),
    )
        .into_response()
}
async fn setup(State(app): State<App>, Json(creds): Json<Credentials>) -> Response {
    if app.trusted_access.is_some() {
        return result(StatusCode::NOT_IMPLEMENTED, "UNSUPPORTED");
    }
    if creds.password.len() < 12 || creds.password.len() > 1024 {
        return result(StatusCode::BAD_REQUEST, "INVALID_PASSWORD");
    }
    {
        let mut auth = app.auth.inner.lock().unwrap();
        auth.setup_failures.retain(|t| t.elapsed() < LOGIN_LOCKOUT);
        if auth.setup_failures.len() >= MAX_LOGIN_ATTEMPTS as usize {
            return result(StatusCode::TOO_MANY_REQUESTS, "RATE_LIMITED");
        }
        if auth.password.is_some() || auth.bootstrap.as_deref() != Some(creds.token.as_str()) || creds.token.is_empty()
        {
            auth.setup_failures.push(Instant::now());
            return result(StatusCode::FORBIDDEN, "INVALID_BOOTSTRAP");
        }
    }
    let password = creds.password;
    let hash = match tokio::task::spawn_blocking(move || {
        Argon2::default()
            .hash_password(password.as_bytes())
            .map(|h| h.to_string())
    })
    .await
    {
        Ok(Ok(hash)) => hash,
        _ => return result(StatusCode::INTERNAL_SERVER_ERROR, "AUTH_ERROR"),
    };
    // Serialize competing setups, rechecking after the expensive hash. Persistence
    // happens off the async executor and publishes only a complete, synced file.
    let inner = app.auth.inner.clone();
    let path = app.auth.path.clone();
    let bootstrap_path = app.auth.bootstrap_path.clone();
    let token = creds.token;
    match tokio::task::spawn_blocking(move || {
        let mut auth = inner.lock().unwrap();
        if auth.password.is_some() || auth.bootstrap.as_deref() != Some(token.as_str()) {
            return Err("INVALID_BOOTSTRAP");
        }
        if let Some(path) = &path {
            crate::private_file::publish_private(path, hash.as_bytes()).map_err(|_| "AUTH_STORAGE_ERROR")?;
        }
        auth.setup_failures.clear();
        auth.password = Some(hash);
        auth.bootstrap = None;
        if let Some(path) = bootstrap_path {
            let _ = std::fs::remove_file(path);
        }
        Ok(issue_session(&mut auth))
    })
    .await
    {
        Ok(Ok(response)) => response,
        Ok(Err("INVALID_BOOTSTRAP")) => result(StatusCode::FORBIDDEN, "INVALID_BOOTSTRAP"),
        _ => result(StatusCode::INTERNAL_SERVER_ERROR, "AUTH_STORAGE_ERROR"),
    }
}
async fn login_info(State(app): State<App>, headers: HeaderMap) -> Json<serde_json::Value> {
    if app.trusted_access.is_some() {
        return Json(serde_json::json!({"enabled":false,"has_password":false,"authenticated":true}));
    }
    let auth = app.auth.inner.lock().unwrap();
    Json(
        serde_json::json!({"enabled":true,"has_password":auth.password.is_some(),"authenticated":cookie(&headers).is_some_and(|id| auth.sessions.get(id).is_some_and(|e| *e > Instant::now()))}),
    )
}
async fn login(
    State(app): State<App>, axum::extract::ConnectInfo(peer): axum::extract::ConnectInfo<SocketAddr>,
    Json(creds): Json<Credentials>,
) -> Response {
    if app.trusted_access.is_some() {
        return result(StatusCode::NOT_IMPLEMENTED, "UNSUPPORTED");
    }
    if creds.password.len() > 1024 {
        return result(StatusCode::BAD_REQUEST, "INVALID_PASSWORD");
    }
    let permit = match app.login_capacity.clone().try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => return result(StatusCode::TOO_MANY_REQUESTS, "RATE_LIMITED"),
    };
    let hash = {
        let auth = app.auth.inner.lock().unwrap();
        auth.password.clone()
    };
    {
        let mut auth = app.auth.inner.lock().unwrap();
        let Auth {
            login_attempts,
            global_login_attempts,
            ..
        } = &mut *auth;
        match reserve_login_attempt(login_attempts, global_login_attempts, peer.ip(), Instant::now()) {
            LoginReservation::Accepted(_) => (),
            LoginReservation::Limited => return result(StatusCode::TOO_MANY_REQUESTS, "RATE_LIMITED"),
        }
    }
    let password = creds.password;
    let valid = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        hash.as_deref()
            .and_then(|h| PasswordHash::new(h).ok())
            .is_some_and(|h| Argon2::default().verify_password(password.as_bytes(), &h).is_ok())
    })
    .await
    .unwrap_or(false);
    if !valid {
        return result(StatusCode::UNAUTHORIZED, "INVALID_CREDENTIALS");
    }
    let mut auth = app.auth.inner.lock().unwrap();
    auth.login_attempts.remove(&peer.ip());
    issue_session(&mut auth)
}
fn issue_session(auth: &mut Auth) -> Response {
    auth.sessions.retain(|_, e| *e > Instant::now());
    if auth.sessions.len() >= 64 {
        auth.sessions.clear();
    }
    let id = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
    auth.sessions
        .insert(id.clone(), Instant::now() + Duration::from_secs(86400));
    (
        [(
            header::SET_COOKIE,
            format!("session_id={id}; HttpOnly; SameSite=Strict; Path=/"),
        )],
        Json(serde_json::json!({"success":true})),
    )
        .into_response()
}
async fn platform(State(app): State<App>) -> Response {
    if app.preview {
        return Json(crate::platform::PlatformInfo {
            platform: "unsupported",
            core: "mihomo",
            capabilities: vec!["platform_inspect"],
            unsupported_reasons: vec!["Offline preview has no router runtime"],
        })
        .into_response();
    }
    let mut info = Platform::inspect();
    if info.platform == "openwrt" {
        let capabilities = if let Ok(permit) = app.runtime_capacity.clone().try_acquire_owned() {
            let status = tokio::time::timeout(
                Duration::from_secs(3),
                tokio::task::spawn_blocking(move || {
                    let _permit = permit;
                    crate::runtime::ipc::RuntimeClient::status()
                }),
            )
            .await;
            match status {
                Ok(Ok(Ok(reply))) if reply.code == "OK" => reply.capabilities,
                _ => None,
            }
        } else {
            None
        };
        expose_runtime_capabilities(&mut info, capabilities.as_deref());
    }
    Json(info).into_response()
}
async fn app_info(State(app): State<App>) -> Response {
    let package_version = option_env!("XKEENWRT_PACKAGE_VERSION").unwrap_or("development");
    let build_id = option_env!("XKEENWRT_BUILD_ID").unwrap_or("unpackaged");
    Json(serde_json::json!({
        "success": true,
        "ui_base_version": "1.4.3",
        "package_version": package_version,
        "build_id": build_id,
        "upstream_commit": "109742570ce0006bdc20e9b87eaa8ba8731d08a7",
        "management_scope":if app.trusted_access.as_ref().is_some_and(|a|a.is_overlay()) {"tailscale_admin"} else {"lan_admin"},
    }))
    .into_response()
}
fn expose_runtime_capabilities(
    info: &mut crate::platform::PlatformInfo, reported: Option<&[crate::runtime::RuntimeCapability]>,
) {
    use crate::runtime::RuntimeCapability as Capability;
    if info.platform != "openwrt" {
        return;
    }
    let Some(reported) = reported else {
        info.unsupported_reasons = vec!["Native runtime status is unavailable"];
        return;
    };
    info.capabilities.extend(
        reported
            .iter()
            .copied()
            .map(Capability::as_str)
            .filter(|cap| *cap != "platform_inspect"),
    );
    info.unsupported_reasons = [
        (Capability::CoreControl, "Native core control is unavailable"),
        (
            Capability::ProfileValidate,
            "Native profile validation prerequisites are unavailable",
        ),
        (
            Capability::ProfileApplyManual,
            "Manual apply and persistent recovery prerequisites are unavailable",
        ),
        (
            Capability::CoreRelay,
            "Core monitoring requires the managed core to be running",
        ),
        (
            Capability::ProviderRefresh,
            "Native provider refresh prerequisites are unavailable",
        ),
        (
            Capability::NetworkIntegration,
            "Native network integration prerequisites are unavailable",
        ),
    ]
    .into_iter()
    .filter_map(|(capability, reason)| (!reported.contains(&capability)).then_some(reason))
    .collect();
}
async fn dns_status(State(app): State<App>) -> Response {
    if app.preview {
        return result(StatusCode::SERVICE_UNAVAILABLE, "UNSUPPORTED");
    }
    match tokio::task::spawn_blocking(crate::system::dns_snapshot).await {
        Ok(Ok(status)) => Json(status).into_response(),
        _ => result(StatusCode::SERVICE_UNAVAILABLE, "UNAVAILABLE"),
    }
}
async fn control_status(State(app): State<App>, headers: HeaderMap) -> Response {
    status_response(app, headers, false).await
}
async fn status_response(app: App, headers: HeaderMap, inputs_only: bool) -> Response {
    if app.preview {
        return result(StatusCode::SERVICE_UNAVAILABLE, "UNSUPPORTED");
    }
    // Browser cache directives concern HTTP storage, not the authority of a
    // runtime observation. Only operation verification requests this barrier.
    let fresh = headers.get("x-xkeenwrt-status-fresh").is_some_and(|v| v == "1");
    match app.status_snapshot.read(&app, fresh).await {
        Ok(value) if inputs_only => Json(serde_json::json!({"success":true,"network":value["inputs"],"stale":value["stale"],"observed_age_ms":value["observed_age_ms"]})).into_response(),
        Ok(value) => Json(value).into_response(),
        Err(code) => result(StatusCode::SERVICE_UNAVAILABLE, &code),
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ValidateRequest {
    expected_revision: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CancelCandidateRequest {
    expected_revision: String,
    candidate_id: String,
}
async fn cancel_profile_candidate(
    State(app): State<App>, Path(id): Path<String>, Json(req): Json<CancelCandidateRequest>,
) -> Response {
    if id.len() > 64 || req.expected_revision.len() > 64 || req.candidate_id.len() > 64 {
        return result(StatusCode::BAD_REQUEST, "INVALID");
    }
    runtime_request(
        app,
        crate::runtime::RuntimeCommand::CancelCandidate {
            profile_id: id,
            revision: req.expected_revision,
            candidate_id: req.candidate_id,
        },
    )
    .await
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ApplyRequest {
    expected_revision: String,
    candidate_id: String,
    idempotency_key: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ControlRequest {
    action: String,
    #[serde(default)]
    request_id: Option<String>,
}
impl ControlRequest {
    fn into_command(self) -> Option<crate::runtime::RuntimeCommand> {
        match (self.action.as_str(), self.request_id) {
            ("start", None) => Some(crate::runtime::RuntimeCommand::Start),
            ("stop", None) => Some(crate::runtime::RuntimeCommand::Stop),
            ("restart", None) => Some(crate::runtime::RuntimeCommand::Restart),
            ("resume_after_reinstall", Some(request_id)) => {
                Some(crate::runtime::RuntimeCommand::ResumeAfterReinstall { request_id })
            }
            _ => None,
        }
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NetworkPlanBody {
    profile_id: String,
    expected_revision: String,
    candidate_id: String,
    lan_interface: String,
    selected_ipv4: std::net::Ipv4Addr,
    management_ipv4: std::net::Ipv4Addr,
    selected_ipv6: Vec<String>,
    management_ipv6: Vec<String>,
    ipv6_policy: String,
    failure_policy: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NetworkApplyBody {
    plan_id: String,
    idempotency_key: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NetworkConfirmBody {
    transaction_id: String,
    confirm_token: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NetworkDisableBody {
    idempotency_key: String,
}
/// The administrator of a request as the accepting listener sees it: the
/// Tailscale listener yields a Tailscale peer, any other an IPv4 LAN peer.
fn management_peer(app: &App, peer: SocketAddr) -> Option<crate::management::ManagementPeer> {
    match &app.trusted_access {
        Some(access) => access.management_peer(peer.ip()),
        None => match peer.ip() {
            std::net::IpAddr::V4(peer) => Some(crate::management::ManagementPeer::Lan { peer }),
            std::net::IpAddr::V6(_) => None,
        },
    }
}
async fn network_plan(
    State(app): State<App>, axum::extract::ConnectInfo(peer): axum::extract::ConnectInfo<SocketAddr>,
    Json(body): Json<NetworkPlanBody>,
) -> Response {
    // Selecting a pilot client and its failure policy stays a main-LAN action.
    if app.trusted_access.as_ref().is_some_and(|a| a.is_overlay()) {
        return result(StatusCode::FORBIDDEN, "NETWORK_MANAGEMENT");
    }
    let std::net::IpAddr::V4(peer_ipv4) = peer.ip() else {
        return result(StatusCode::BAD_REQUEST, "INVALID");
    };
    if body.management_ipv4 != peer_ipv4
        || body.selected_ipv6.len() > 8
        || body.management_ipv6.len() > 8
        || body
            .selected_ipv6
            .iter()
            .chain(&body.management_ipv6)
            .any(|s| s.len() > 43)
        || body.profile_id.len() > 64
        || body.expected_revision.len() > 64
        || body.candidate_id.len() > 64
        || body.lan_interface.len() > 15
        || body.ipv6_policy != "block_external"
        || !matches!(
            body.failure_policy.as_str(),
            "direct_on_failure" | "block_selected_on_failure"
        )
    {
        return result(StatusCode::BAD_REQUEST, "INVALID");
    }
    let request = crate::runtime::NetworkPlanRequest {
        profile_id: body.profile_id,
        expected_revision: body.expected_revision,
        candidate_id: body.candidate_id,
        lan_interface: body.lan_interface,
        selected_ipv4: body.selected_ipv4,
        management_ipv4: body.management_ipv4,
        selected_ipv6: body.selected_ipv6,
        management_ipv6: body.management_ipv6,
        ipv6_policy: body.ipv6_policy,
        failure_policy: body.failure_policy,
        peer_ipv4,
        tailscale_router: None,
    };
    runtime_request(app, crate::runtime::RuntimeCommand::NetworkPlan { request }).await
}
async fn network_apply(State(app): State<App>, Json(body): Json<NetworkApplyBody>) -> Response {
    if body.plan_id.len() > 64 || body.idempotency_key.len() > 128 {
        return result(StatusCode::BAD_REQUEST, "INVALID");
    }
    runtime_request(
        app,
        crate::runtime::RuntimeCommand::NetworkApply {
            plan_id: body.plan_id,
            idempotency_key: body.idempotency_key,
        },
    )
    .await
}
async fn network_confirm(State(app): State<App>, Json(body): Json<NetworkConfirmBody>) -> Response {
    if body.transaction_id.len() > 64 || body.confirm_token.len() > 128 {
        return result(StatusCode::BAD_REQUEST, "INVALID");
    }
    runtime_request(
        app,
        crate::runtime::RuntimeCommand::NetworkConfirm {
            transaction_id: body.transaction_id,
            confirm_token: body.confirm_token,
        },
    )
    .await
}
async fn network_compatibility(
    State(app): State<App>, axum::extract::ConnectInfo(peer): axum::extract::ConnectInfo<SocketAddr>,
) -> Response {
    let Some(peer) = management_peer(&app, peer) else {
        return result(StatusCode::BAD_REQUEST, "INVALID");
    };
    runtime_request(app, crate::runtime::RuntimeCommand::Compatibility { peer }).await
}
async fn network_status(State(app): State<App>) -> Response {
    runtime_request(app, crate::runtime::RuntimeCommand::NetworkStatus).await
}
async fn network_disable(State(app): State<App>, Json(body): Json<NetworkDisableBody>) -> Response {
    if body.idempotency_key.is_empty()
        || body.idempotency_key.len() > 128
        || !body
            .idempotency_key
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return result(StatusCode::BAD_REQUEST, "INVALID");
    }
    runtime_request(
        app,
        crate::runtime::RuntimeCommand::NetworkDisable {
            idempotency_key: body.idempotency_key,
        },
    )
    .await
}

#[cfg(test)]
mod login_attempt_tests {
    use super::{LoginReservation, MAX_GLOBAL_LOGIN_ATTEMPTS, reserve_login_attempt};
    use std::{
        collections::{HashMap, VecDeque},
        net::IpAddr,
        time::{Duration, Instant},
    };

    #[test]
    fn global_login_budget_is_bounded_across_sources_and_expires() {
        let now = Instant::now();
        let mut attempts = HashMap::new();
        let mut global_attempts = VecDeque::new();
        for index in 0..MAX_GLOBAL_LOGIN_ATTEMPTS {
            let ip = IpAddr::V6(std::net::Ipv6Addr::from(index as u128));
            assert_eq!(
                reserve_login_attempt(&mut attempts, &mut global_attempts, ip, now),
                LoginReservation::Accepted(1)
            );
        }
        assert_eq!(attempts.len(), MAX_GLOBAL_LOGIN_ATTEMPTS);
        attempts.remove(&IpAddr::V6(std::net::Ipv6Addr::from(0)));
        assert_eq!(
            reserve_login_attempt(&mut attempts, &mut global_attempts, "2001:db8::1".parse().unwrap(), now),
            LoginReservation::Limited
        );
        assert_eq!(
            reserve_login_attempt(
                &mut attempts,
                &mut global_attempts,
                "2001:db8::1".parse().unwrap(),
                now + Duration::from_secs(121),
            ),
            LoginReservation::Accepted(1)
        );
    }

    #[test]
    fn parallel_hash_slots_reject_before_a_blocking_task_is_spawned() {
        use std::sync::Arc;
        let slots = Arc::new(tokio::sync::Semaphore::new(super::MAX_LOGIN_HASHES_IN_FLIGHT));
        let first = slots.clone().try_acquire_owned().unwrap();
        let second = slots.clone().try_acquire_owned().unwrap();
        assert!(slots.clone().try_acquire_owned().is_err());
        drop(first);
        assert!(slots.clone().try_acquire_owned().is_ok());
        drop(second);
    }
}

async fn runtime_request(app: App, command: crate::runtime::RuntimeCommand) -> Response {
    if app.preview {
        return result(StatusCode::SERVICE_UNAVAILABLE, "UNSUPPORTED");
    }
    let permit = match app.runtime_capacity.clone().try_acquire_owned() {
        Ok(p) => p,
        Err(_) => return result(StatusCode::SERVICE_UNAVAILABLE, "BUSY"),
    };
    let _mutation = (!matches!(
        &command,
        crate::runtime::RuntimeCommand::Status
            | crate::runtime::RuntimeCommand::InputsStatus
            | crate::runtime::RuntimeCommand::NetworkStatus
            | crate::runtime::RuntimeCommand::Compatibility { .. }
            | crate::runtime::RuntimeCommand::ProviderContent { .. }
    ))
    .then(|| app.status_snapshot.mutation());
    let explicit_resume = matches!(&command, crate::runtime::RuntimeCommand::ResumeAfterReinstall { .. });
    match tokio::task::spawn_blocking(move || {
        let _permit = permit;
        crate::runtime::ipc::RuntimeClient::command(command)
    })
    .await
    {
        Ok(Ok(reply)) if reply.code == "OK" => runtime_success_response(reply, explicit_resume),
        Ok(Ok(reply)) => runtime_error_response(reply),
        _ => result(StatusCode::SERVICE_UNAVAILABLE, "RUNTIME_UNAVAILABLE"),
    }
}
/// HTTP shape of a refused runtime command.
fn runtime_error_response(reply: crate::runtime::RuntimeReply) -> Response {
    // Compatibility blockers and refused Tailscale probes carry a bounded
    // report the panel shows; their message is the runtime's own text.
    if reply
        .network
        .as_ref()
        .is_some_and(|n| n.get("compatibility").is_some() || n.get("remote_check").is_some())
    {
        return (
            StatusCode::CONFLICT,
            Json(serde_json::json!({"success":false,"code":reply.code,"error":reply.message,"network":reply.network})),
        )
            .into_response();
    }
    if let Some(diagnostic) = reply.diagnostic {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({
                "success":false,"code":"VALIDATION_FAILED","error":diagnostic.message(),
                "stage":diagnostic.stage(),"diagnostic":diagnostic
            })),
        )
            .into_response();
    }
    if matches!(
        reply.code.as_str(),
        "NETWORK_FIREWALL_CONFLICT" | "NETWORK_PORT_CONFLICT"
    ) {
        return (
            StatusCode::CONFLICT,
            Json(serde_json::json!({"success":false,"code":reply.code,"error":reply.message})),
        )
            .into_response();
    }
    let status = match reply.code.as_str() {
        "CONFLICT" => StatusCode::CONFLICT,
        "INVALID" => StatusCode::BAD_REQUEST,
        _ => StatusCode::SERVICE_UNAVAILABLE,
    };
    result(status, &reply.code)
}

fn runtime_success_response(reply: crate::runtime::RuntimeReply, explicit_resume: bool) -> Response {
    if explicit_resume {
        return if reply.running == Some(false) {
            Json(serde_json::json!({"success":true,"running":false})).into_response()
        } else {
            result(StatusCode::SERVICE_UNAVAILABLE, "NOT_READY")
        };
    }
    if let Some(validation) = reply.validation {
        Json(serde_json::json!({"success":true,"validation":validation})).into_response()
    } else if let Some(transaction) = reply.transaction {
        Json(serde_json::json!({"success":true,"transaction":transaction})).into_response()
    } else if let Some(network) = reply.network {
        Json(serde_json::json!({"success":true,"network":network})).into_response()
    } else if let Some(content) = reply.provider_content {
        Json(serde_json::json!({"success":true,"content":content})).into_response()
    } else {
        Json(serde_json::json!({"success":true})).into_response()
    }
}
async fn validate_profile(
    State(app): State<App>, Path(id): Path<String>, Json(req): Json<ValidateRequest>,
) -> Response {
    runtime_request(
        app,
        crate::runtime::RuntimeCommand::Validate {
            profile_id: id,
            revision: req.expected_revision,
        },
    )
    .await
}
async fn apply_profile(
    State(app): State<App>, Path(id): Path<String>,
    axum::extract::ConnectInfo(peer): axum::extract::ConnectInfo<SocketAddr>, Json(req): Json<ApplyRequest>,
) -> Response {
    let Some(peer) = management_peer(&app, peer) else {
        return result(StatusCode::BAD_REQUEST, "INVALID");
    };
    runtime_request(
        app,
        crate::runtime::RuntimeCommand::ServiceApply {
            peer,
            profile_id: id,
            revision: req.expected_revision,
            candidate_id: req.candidate_id,
            idempotency_key: req.idempotency_key,
        },
    )
    .await
}
async fn refresh_profile_provider(
    State(app): State<App>, Path((id, provider_id)): Path<(String, String)>, Json(req): Json<ValidateRequest>,
) -> Response {
    runtime_request(
        app,
        crate::runtime::RuntimeCommand::RefreshProvider {
            profile_id: id,
            revision: req.expected_revision,
            provider_id,
        },
    )
    .await
}
async fn provider_content(
    State(app): State<App>, Path((id, provider_id)): Path<(String, String)>,
    axum::extract::Query(req): axum::extract::Query<ProviderQuery>,
) -> Response {
    if id.len() > 64 || req.expected_revision.len() > 64 || provider_id.len() > 16 {
        return result(StatusCode::BAD_REQUEST, "INVALID");
    }
    runtime_request(
        app,
        crate::runtime::RuntimeCommand::ProviderContent {
            profile_id: id,
            revision: req.expected_revision,
            provider_id,
        },
    )
    .await
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EditProviderRequest {
    expected_revision: String,
    content: String,
}
async fn edit_profile_provider(
    State(app): State<App>, Path((id, provider_id)): Path<(String, String)>, Json(req): Json<EditProviderRequest>,
) -> Response {
    if id.len() > 64
        || req.expected_revision.len() > 64
        || provider_id.len() > 16
        || req.content.len() > 2 * 1024 * 1024
        || req.content.contains('\0')
    {
        return result(StatusCode::BAD_REQUEST, "INVALID");
    }
    runtime_request(
        app,
        crate::runtime::RuntimeCommand::EditProvider {
            profile_id: id,
            revision: req.expected_revision,
            provider_id,
            content: req.content,
        },
    )
    .await
}
async fn control(
    State(app): State<App>, axum::extract::ConnectInfo(peer): axum::extract::ConnectInfo<SocketAddr>,
    Json(req): Json<ControlRequest>,
) -> Response {
    let Some(command) = req.into_command() else {
        return result(StatusCode::BAD_REQUEST, "INVALID");
    };
    let command = match command {
        crate::runtime::RuntimeCommand::Start => {
            let Some(peer) = management_peer(&app, peer) else {
                return result(StatusCode::BAD_REQUEST, "INVALID");
            };
            crate::runtime::RuntimeCommand::ServiceStart { peer }
        }
        crate::runtime::RuntimeCommand::Stop => crate::runtime::RuntimeCommand::ServiceStop,
        crate::runtime::RuntimeCommand::Restart => {
            let Some(peer) = management_peer(&app, peer) else {
                return result(StatusCode::BAD_REQUEST, "INVALID");
            };
            crate::runtime::RuntimeCommand::ServiceRestart { peer }
        }
        other => other,
    };
    runtime_request(app, command).await
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExplicitRequest {
    enabled: bool,
    #[serde(default)]
    binding: Option<crate::runtime::ExplicitBinding>,
}
async fn inputs_status(State(app): State<App>, headers: HeaderMap) -> Response {
    status_response(app, headers, true).await
}
async fn explicit_set(
    State(app): State<App>, axum::extract::ConnectInfo(peer): axum::extract::ConnectInfo<SocketAddr>,
    Json(req): Json<ExplicitRequest>,
) -> Response {
    let Some(peer) = management_peer(&app, peer) else {
        return result(StatusCode::BAD_REQUEST, "INVALID");
    };
    if req.enabled != req.binding.is_some() {
        return result(StatusCode::BAD_REQUEST, "INVALID");
    }
    runtime_request(
        app,
        crate::runtime::RuntimeCommand::ExplicitSet {
            binding: req.binding,
            peer,
        },
    )
    .await
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BackupRequest {
    name: String,
    #[serde(default)]
    contents: Option<Vec<String>>,
    #[serde(default)]
    new_name: Option<String>,
}
async fn backup_operation(app: App, method: &'static str, request: Option<BackupRequest>) -> Response {
    if app.preview {
        return result(StatusCode::SERVICE_UNAVAILABLE, "UNSUPPORTED");
    }
    let Ok(permit) = app.preparation_capacity.clone().try_acquire_owned() else {
        return result(StatusCode::SERVICE_UNAVAILABLE, "BUSY");
    };
    match tokio::task::spawn_blocking(move || {
        let _permit = permit;
        match (method, request) {
            ("GET", _) => crate::backups::list().map(|backups| serde_json::json!({"success":true,"backups":backups})),
            ("PUT", _) => {
                crate::backups::create(&app.profiles).map(|backup| serde_json::json!({"success":true,"backup":backup}))
            }
            ("POST", Some(request)) => crate::backups::restore(&app.profiles, &request.name, request.contents)
                .map(|()| serde_json::json!({"success":true})),
            ("DELETE", Some(request)) => {
                crate::backups::delete(&request.name).map(|()| serde_json::json!({"success":true}))
            }
            ("PATCH", Some(request)) => {
                crate::backups::rename(&request.name, request.new_name.as_deref().unwrap_or(""))
                    .map(|()| serde_json::json!({"success":true}))
            }
            _ => Err("некорректное действие с резервной копией".into()),
        }
    })
    .await
    {
        Ok(Ok(value)) => Json(value).into_response(),
        Ok(Err(error)) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"success":false,"error":error})),
        )
            .into_response(),
        Err(_) => result(StatusCode::SERVICE_UNAVAILABLE, "STORAGE_ERROR"),
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResourceUpload {
    expected_revision: String,
    name: String,
    content_base64: String,
}
async fn resources_get(State(app): State<App>, Path(id): Path<String>) -> Response {
    let operation = move || {
        ConfigStore::new(&app.profiles)
            .and_then(|store| store.read(&id))
            .map_err(|_| "Профиль не найден")?;
        crate::resources::list(&id).map(|resources| serde_json::json!({"success":true,"resources":resources}))
    };
    diagnostic_response(tokio::task::spawn_blocking(operation).await).await
}
async fn resources_upload(
    State(app): State<App>, Path(id): Path<String>, Json(request): Json<ResourceUpload>,
) -> Response {
    if app.preview {
        return result(StatusCode::SERVICE_UNAVAILABLE, "UNSUPPORTED");
    }
    let Ok(permit) = app.preparation_capacity.clone().try_acquire_owned() else {
        return result(StatusCode::SERVICE_UNAVAILABLE, "BUSY");
    };
    diagnostic_response(
        tokio::task::spawn_blocking(move || {
            use base64::Engine;
            let _permit = permit;
            if request.content_base64.len() > 12 * 1024 * 1024 {
                return Err("Ресурс слишком большой");
            }
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(&request.content_base64)
                .map_err(|_| "Некорректный файл")?;
            let store = ConfigStore::new(&app.profiles).map_err(|_| "Хранилище профиля недоступно")?;
            let resource = crate::resources::upload(&store, &id, &request.expected_revision, &request.name, &bytes)?;
            Ok(serde_json::json!({"success":true,"resource":resource}))
        })
        .await,
    )
    .await
}
async fn diagnostic_response(
    result: Result<Result<serde_json::Value, &'static str>, tokio::task::JoinError>,
) -> Response {
    match result {
        Ok(Ok(value)) => Json(value).into_response(),
        Ok(Err(error)) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"success":false,"error":error})),
        )
            .into_response(),
        Err(_) => result_error(),
    }
}
fn result_error() -> Response {
    result(StatusCode::SERVICE_UNAVAILABLE, "NOT_READY")
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GeoQuery {
    profile_id: String,
    file: Option<String>,
    domain: Option<String>,
    ip: Option<String>,
}
async fn geo_operation(app: App, query: GeoQuery, kind: &'static str) -> Response {
    let Ok(permit) = app.preparation_capacity.clone().try_acquire_owned() else {
        return result(StatusCode::SERVICE_UNAVAILABLE, "BUSY");
    };
    diagnostic_response(tokio::task::spawn_blocking(move || {
        let _permit = permit;
        ConfigStore::new(&app.profiles).and_then(|store| store.read(&query.profile_id)).map_err(|_| "Профиль не найден")?;
        if kind == "list" {
            let mut sites = Vec::new(); let mut ips = Vec::new();
            for resource in crate::resources::list(&query.profile_id)? {
                if !matches!(resource.format.as_str(), "dat" | "mrs") { continue; }
                let bytes = crate::resources::read(&query.profile_id, &resource.id)?;
                if resource.format == "mrs" {
                    let mrs = crate::rule_resources::read_mrs(&bytes)?;
                    if mrs.behavior == "domain" { sites.push(resource.id); } else { ips.push(resource.id); }
                } else if crate::rule_resources::dat_categories(&bytes, "example.invalid", false).is_ok() { sites.push(resource.id); }
                else if crate::rule_resources::dat_categories(&bytes, "192.0.2.1", true).is_ok() { ips.push(resource.id); }
            }
            return Ok(serde_json::json!({"success":true,"site_files":sites,"ip_files":ips,"formats":["GeoSite DAT","GeoIP DAT","MRS v1 domain","MRS v1 ipcidr"]}));
        }
        let file = query.file.ok_or("Файл не выбран")?;
        let target = if kind == "ip" { query.ip } else { query.domain }.ok_or("Введите домен или IP")?;
        if target.is_empty() || target.len() > 253 { return Err("Некорректная цель"); }
        let bytes = crate::resources::read(&query.profile_id, &file)?;
        let categories = if file.ends_with(".mrs") {
            let mrs = crate::rule_resources::read_mrs(&bytes)?;
            let mut found = false;
            for rule in mrs.rules {
                found |= match (mrs.behavior, kind) {
                    ("domain", "site") => crate::rule_resources::domain_pattern(&target, &rule),
                    ("ipcidr", "ip") => crate::rule_resources::cidr_matches(target.parse().map_err(|_| "Введите IP-адрес")?, &rule)?,
                    _ => return Err("Тип MRS не совпадает с запросом"),
                };
                if found { break; }
            }
            if found { vec![file] } else { vec![] }
        } else if file.ends_with(".dat") { crate::rule_resources::dat_categories(&bytes, &target, kind == "ip")? }
        else { return Err("Поддерживаются GeoSite/GeoIP DAT и MRS v1"); };
        Ok(serde_json::json!({"success":true,"categories":categories}))
    }).await).await
}
async fn geo_get(State(app): State<App>, Query(query): Query<GeoQuery>) -> Response {
    geo_operation(app, query, "list").await
}
async fn geo_ip(State(app): State<App>, Query(query): Query<GeoQuery>) -> Response {
    geo_operation(app, query, "ip").await
}
async fn geo_site(State(app): State<App>, Query(query): Query<GeoQuery>) -> Response {
    geo_operation(app, query, "site").await
}
async fn route_init() -> Response {
    Json(serde_json::json!({"success":true,"core":"mihomo","inboundTags":[]})).into_response()
}
async fn route_run(State(app): State<App>, Json(request): Json<crate::diagnostics::RouteRequest>) -> Response {
    let Ok(permit) = app.preparation_capacity.clone().try_acquire_owned() else {
        return result(StatusCode::SERVICE_UNAVAILABLE, "BUSY");
    };
    diagnostic_response(
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let store = ConfigStore::new(&app.profiles).map_err(|_| "Хранилище недоступно")?;
            let profile = store.read(&request.profile_id).map_err(|_| "Профиль не найден")?;
            if profile.revision != request.expected_revision {
                return Err("Профиль изменился; обновите его перед проверкой");
            }
            crate::diagnostics::routes(&profile.source, &request)
        })
        .await,
    )
    .await
}
async fn backups_get(State(app): State<App>) -> Response {
    backup_operation(app, "GET", None).await
}
async fn backups_create(State(app): State<App>) -> Response {
    backup_operation(app, "PUT", None).await
}
async fn backups_restore(State(app): State<App>, Json(request): Json<BackupRequest>) -> Response {
    backup_operation(app, "POST", Some(request)).await
}
async fn backups_delete(State(app): State<App>, Json(request): Json<BackupRequest>) -> Response {
    backup_operation(app, "DELETE", Some(request)).await
}
async fn backups_rename(State(app): State<App>, Json(request): Json<BackupRequest>) -> Response {
    backup_operation(app, "PATCH", Some(request)).await
}
async fn system_status() -> Response {
    match tokio::task::spawn_blocking(crate::system::snapshot).await {
        Ok(Ok(stats)) => Json(serde_json::json!({
            "success": true,
            "memoryUsed": stats.memory_used,
            "memoryTotal": stats.memory_total,
            "cpuUsage": stats.cpu_usage,
            "source": "openwrt-host",
        }))
        .into_response(),
        _ => result(StatusCode::SERVICE_UNAVAILABLE, "STATS_UNAVAILABLE"),
    }
}
async fn core_catalog(State(app): State<App>) -> Response {
    Json(app.core_updates.catalog()).into_response()
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CoreUpdateRequest {
    version: String,
}
async fn core_update_start(State(app): State<App>, Json(req): Json<CoreUpdateRequest>) -> Response {
    if app.preview {
        return result(StatusCode::SERVICE_UNAVAILABLE, "UNSUPPORTED");
    }
    if !matches!(Platform::service_status(), Ok(crate::platform::ServiceStatus::Stopped)) {
        return result(StatusCode::CONFLICT, "CONFLICT");
    }
    match app.core_updates.start(&req.version) {
        Ok(()) => Json(serde_json::json!({"success":true})).into_response(),
        Err("Unsupported Mihomo release") => result(StatusCode::BAD_REQUEST, "UNSUPPORTED"),
        Err("A Mihomo update is already running") => result(StatusCode::CONFLICT, "BUSY"),
        Err(_) => result(StatusCode::SERVICE_UNAVAILABLE, "NOT_READY"),
    }
}
// Panel self-update (decision 026): newer releases only, gateway stopped.
async fn self_catalog(State(app): State<App>) -> Response {
    if app.preview {
        return result(StatusCode::SERVICE_UNAVAILABLE, "UNSUPPORTED");
    }
    match app.self_update.catalog().await {
        Ok((current, releases)) => Json(serde_json::json!({
            "success": true,
            "repository": crate::self_update::REPO,
            "current": current.to_string(),
            "releases": releases,
        }))
        .into_response(),
        Err(code) => self_update_error(code),
    }
}
async fn self_update_start(State(app): State<App>, Json(req): Json<CoreUpdateRequest>) -> Response {
    if app.preview {
        return result(StatusCode::SERVICE_UNAVAILABLE, "UNSUPPORTED");
    }
    if !matches!(Platform::service_status(), Ok(crate::platform::ServiceStatus::Stopped)) {
        return result(StatusCode::CONFLICT, "GATEWAY_RUNNING");
    }
    match app.self_update.start(&req.version).await {
        Ok(()) => Json(serde_json::json!({"success":true})).into_response(),
        Err(code) => self_update_error(code),
    }
}
async fn self_update_status(State(app): State<App>) -> Response {
    if app.preview {
        return result(StatusCode::SERVICE_UNAVAILABLE, "UNSUPPORTED");
    }
    let status = app.self_update.status().await;
    let mut body = serde_json::to_value(&status).unwrap_or_default();
    body["success"] = true.into();
    body["current"] = option_env!("XKEENWRT_PACKAGE_VERSION").unwrap_or("development").into();
    Json(body).into_response()
}
fn self_update_error(code: &'static str) -> Response {
    let status = match code {
        "UPDATE_RUNNING" => StatusCode::CONFLICT,
        "NOT_NEWER" | "UNKNOWN_RELEASE" => StatusCode::BAD_REQUEST,
        "INSTALLER_INVALID" | "GITHUB_UNAVAILABLE" => StatusCode::BAD_GATEWAY,
        _ => StatusCode::SERVICE_UNAVAILABLE,
    };
    result(status, code)
}
async fn core_update_cancel(State(app): State<App>) -> Response {
    match app.core_updates.cancel() {
        Ok(()) => Json(serde_json::json!({"success":true})).into_response(),
        Err(_) => result(StatusCode::CONFLICT, "CONFLICT"),
    }
}
async fn core_update_rollback(State(app): State<App>) -> Response {
    if !matches!(Platform::service_status(), Ok(crate::platform::ServiceStatus::Stopped)) {
        return result(StatusCode::CONFLICT, "CONFLICT");
    }
    match tokio::task::spawn_blocking(move || app.core_updates.rollback()).await {
        Ok(Ok(version)) => Json(serde_json::json!({"success":true,"version":version})).into_response(),
        _ => result(StatusCode::SERVICE_UNAVAILABLE, "NOT_READY"),
    }
}
async fn core_update_ws(State(app): State<App>, ws: axum::extract::ws::WebSocketUpgrade) -> Response {
    if app.preview {
        return result(StatusCode::SERVICE_UNAVAILABLE, "UNSUPPORTED");
    }
    let permit = match app.websocket_capacity.clone().try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => return result(StatusCode::SERVICE_UNAVAILABLE, "BUSY"),
    };
    let events = app.core_updates.events();
    let access = app.trusted_access.clone();
    ws.max_message_size(4096)
        .max_frame_size(4096)
        .on_upgrade(move |mut socket| {
            scoped_stream(access, async move {
                let _permit = permit;
                let Some((history, mut receiver)) = events else {
                    let _ = socket
                        .send(axum::extract::ws::Message::Text(
                            serde_json::json!({"type":"update","history":[]}).to_string().into(),
                        ))
                        .await;
                    return;
                };
                if socket
                    .send(axum::extract::ws::Message::Text(
                        serde_json::json!({"type":"update","history":history})
                            .to_string()
                            .into(),
                    ))
                    .await
                    .is_err()
                {
                    return;
                }
                loop {
                    tokio::select! {
                        event = receiver.recv() => match event {
                            Ok(event) => {
                                if socket.send(axum::extract::ws::Message::Text(
                                    serde_json::json!({"type":"update","event":event}).to_string().into()
                                )).await.is_err() { break; }
                                if event.kind == "done" { break; }
                            }
                            Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                            Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                        },
                        incoming = socket.recv() => match incoming {
                            Some(Ok(axum::extract::ws::Message::Ping(bytes))) => {
                                if socket.send(axum::extract::ws::Message::Pong(bytes)).await.is_err() { break; }
                            }
                            Some(Ok(axum::extract::ws::Message::Close(_))) | None | Some(Err(_)) => break,
                            _ => (),
                        }
                    }
                }
            })
        })
}
async fn core_relay(
    State(app): State<App>, uri: axum::http::Uri, method: axum::http::Method, body: axum::body::Bytes,
) -> Response {
    if app.preview {
        return result(StatusCode::SERVICE_UNAVAILABLE, "UNSUPPORTED");
    }
    let _permit = match app.relay_capacity.clone().try_acquire_owned() {
        Ok(p) => p,
        Err(_) => return result(StatusCode::SERVICE_UNAVAILABLE, "BUSY"),
    };
    let secret = match read_private_file(std::path::Path::new("/etc/xkeenwrt/controller-secret")) {
        Ok(v) if v.len() == 64 && v.bytes().all(|b| b.is_ascii_hexdigit()) => v,
        _ => return result(StatusCode::SERVICE_UNAVAILABLE, "NOT_READY"),
    };
    let Some(path) = uri.path().strip_prefix("/api/core/") else {
        return result(StatusCode::BAD_REQUEST, "INVALID");
    };
    crate::mihomo::http(method, path, uri.query(), body, &secret).await
}
async fn core_ws(
    State(app): State<App>, Path(stream): Path<String>, uri: axum::http::Uri, ws: axum::extract::ws::WebSocketUpgrade,
) -> Response {
    if app.preview {
        return result(StatusCode::SERVICE_UNAVAILABLE, "UNSUPPORTED");
    }
    let permit = match app.websocket_capacity.clone().try_acquire_owned() {
        Ok(p) => p,
        Err(_) => return result(StatusCode::SERVICE_UNAVAILABLE, "BUSY"),
    };
    if !matches!(stream.as_str(), "logs" | "traffic" | "memory" | "connections") || uri.query().is_some() {
        return result(StatusCode::BAD_REQUEST, "INVALID");
    }
    let secret = match read_private_file(std::path::Path::new("/etc/xkeenwrt/controller-secret")) {
        Ok(v) if v.len() == 64 && v.bytes().all(|b| b.is_ascii_hexdigit()) => v,
        _ => return result(StatusCode::SERVICE_UNAVAILABLE, "NOT_READY"),
    };
    let access = app.trusted_access.clone();
    ws.max_message_size(16 * 1024)
        .max_frame_size(16 * 1024)
        .on_upgrade(move |socket| {
            scoped_stream(access, async move {
                let _permit = permit;
                crate::mihomo::websocket(socket, &stream, None, &secret).await
            })
        })
}
async fn scoped_stream(
    access: Option<crate::management::TrustedAccess>, stream: impl std::future::Future<Output = ()>,
) {
    match access.filter(|a| a.is_overlay()) {
        Some(policy) => scoped_stream_until(move || policy.boundary_current(), stream).await,
        None => stream.await,
    }
}
async fn scoped_stream_until(current: impl Fn() -> bool, stream: impl std::future::Future<Output = ()>) {
    if !current() {
        return;
    }
    // Upgraded tasks outlive the accept loop. Revocation drops idle sockets
    // and capacity permits even without another request or client frame.
    tokio::select! {
        biased;
        _=async {loop {tokio::time::sleep(Duration::from_secs(1)).await;if !current(){break;}}}=>(),
        _=stream=>(),
    }
}
fn log_html(lines: &[String], filter: &str) -> Vec<String> {
    let needle = filter.to_ascii_lowercase();
    lines
        .iter()
        .filter(|line| needle.is_empty() || line.to_ascii_lowercase().contains(&needle))
        .map(|line| crate::system_log::html_line(line))
        .collect()
}
fn log_overlap(previous: &[String], current: &[String]) -> Option<usize> {
    (1..=previous.len().min(current.len()))
        .rev()
        .find(|count| previous[previous.len() - count..] == current[..*count])
}
async fn system_log_ws(
    State(app): State<App>, uri: axum::http::Uri, ws: axum::extract::ws::WebSocketUpgrade,
) -> Response {
    if app.preview || uri.query() != Some("file=system.log") {
        return result(StatusCode::SERVICE_UNAVAILABLE, "UNSUPPORTED");
    }
    let permit = match app.websocket_capacity.clone().try_acquire_owned() {
        Ok(p) => p,
        Err(_) => return result(StatusCode::SERVICE_UNAVAILABLE, "BUSY"),
    };
    let access = app.trusted_access.clone();
    ws.max_message_size(4096)
        .max_frame_size(4096)
        .on_upgrade(move |mut socket| scoped_stream(access,async move {
            let _permit = permit;
            let mut filter = String::new();
            let mut previous = match crate::system_log::snapshot().await {
                Ok(lines) => lines,
                Err(_) => {
                    let _ = socket
                        .send(axum::extract::ws::Message::Text(
                            serde_json::json!({"type":"error","error":"Журнал OpenWrt недоступен"})
                                .to_string()
                                .into(),
                        ))
                        .await;
                    return;
                }
            };
            let initial = log_html(&previous, &filter);
            if socket
                .send(axum::extract::ws::Message::Text(
                    serde_json::json!({"type":"initial","lines":initial}).to_string().into(),
                ))
                .await
                .is_err()
            {
                return;
            }
            let mut interval = tokio::time::interval(Duration::from_secs(2));
            interval.tick().await;
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        let current = match crate::system_log::snapshot().await {
                            Ok(lines) => lines,
                            Err(_) => {
                                let _ = socket.send(axum::extract::ws::Message::Text(serde_json::json!({"type":"error","error":"Поток собственного журнала недоступен; данные устарели"}).to_string().into())).await;
                                break;
                            }
                        };
                        if current == previous { continue; }
                        if let Some(overlap) = log_overlap(&previous, &current) {
                            let appended = log_html(&current[overlap..], &filter);
                            if !appended.is_empty() && socket.send(axum::extract::ws::Message::Text(
                                serde_json::json!({"type":"append","content":appended.join("")}).to_string().into()
                            )).await.is_err() { break; }
                        } else {
                            let lines = log_html(&current, &filter);
                            if socket.send(axum::extract::ws::Message::Text(
                                serde_json::json!({"type":"initial","lines":lines}).to_string().into()
                            )).await.is_err() { break; }
                        }
                        previous = current;
                    }
                    incoming = socket.recv() => match incoming {
                        Some(Ok(axum::extract::ws::Message::Text(text))) if text.len() <= 4096 => {
                            let Ok(request) = serde_json::from_str::<serde_json::Value>(&text) else { continue };
                            let kind = request.get("type").and_then(|v| v.as_str()).unwrap_or("");
                            match kind {
                                "reload" => filter = request.get("query").and_then(|v| v.as_str()).unwrap_or("").chars().take(128).collect(),
                                "filter" => filter = request.get("query").and_then(|v| v.as_str()).unwrap_or("").chars().take(128).collect(),
                                "switchFile" if request.get("file").and_then(|v| v.as_str()) == Some("system.log") => (),
                                "clear" => {
                                    if crate::system_log::clear().await.is_err() { break; }
                                    previous.clear();
                                    if socket.send(axum::extract::ws::Message::Text(serde_json::json!({"type":"clear"}).to_string().into())).await.is_err() { break; }
                                    continue;
                                }
                                _ => continue,
                            }
                            let lines = log_html(&previous, &filter);
                            if socket.send(axum::extract::ws::Message::Text(
                                serde_json::json!({"type":"filtered","lines":lines}).to_string().into()
                            )).await.is_err() { break; }
                        }
                        Some(Ok(axum::extract::ws::Message::Ping(bytes))) => {
                            if socket.send(axum::extract::ws::Message::Pong(bytes)).await.is_err() { break; }
                        }
                        Some(Ok(axum::extract::ws::Message::Close(_))) | None | Some(Err(_)) => break,
                        _ => (),
                    }
                }
            }
        }))
}
async fn fallback(uri: axum::http::Uri) -> Response {
    if uri.path().starts_with("/api/") || uri.path().starts_with("/ws/") || uri.path().starts_with("/clash") {
        result(StatusCode::NOT_IMPLEMENTED, "UNSUPPORTED")
    } else {
        crate::frontend_embedder::serve(uri).await
    }
}
async fn logout(State(app): State<App>, headers: HeaderMap) -> Response {
    if app.trusted_access.is_some() {
        return Json(serde_json::json!({"success":true})).into_response();
    }
    if let Some(id) = cookie(&headers) {
        app.auth.inner.lock().unwrap().sessions.remove(id);
    }
    (
        [(
            header::SET_COOKIE,
            "session_id=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0",
        )],
        Json(serde_json::json!({"success":true})),
    )
        .into_response()
}
fn config_error(error: crate::configuration::ConfigError) -> Response {
    use crate::configuration::ConfigError::*;
    let (status, code) = match error {
        InvalidId => (StatusCode::BAD_REQUEST, "INVALID_ID"),
        InvalidYaml => (StatusCode::BAD_REQUEST, "INVALID_YAML"),
        TooLarge => (StatusCode::PAYLOAD_TOO_LARGE, "TOO_LARGE"),
        NotFound => (StatusCode::NOT_FOUND, "NOT_FOUND"),
        Conflict => (StatusCode::CONFLICT, "CONFLICT"),
        LimitReached => (StatusCode::CONFLICT, "LIMIT_REACHED"),
        InsufficientSpace => (StatusCode::INSUFFICIENT_STORAGE, "INSUFFICIENT_SPACE"),
        UnsafePath | Storage => (StatusCode::INTERNAL_SERVER_ERROR, "STORAGE_ERROR"),
        Busy => (StatusCode::SERVICE_UNAVAILABLE, "BUSY"),
        CommitUncertain => (StatusCode::INTERNAL_SERVER_ERROR, "COMMIT_UNCERTAIN"),
    };
    result(status, code)
}
fn profile_json(p: crate::configuration::Profile) -> serde_json::Value {
    serde_json::json!({"id":p.id,"revision":p.revision,"source":p.source})
}
async fn list_profiles(State(app): State<App>) -> Response {
    match tokio::task::spawn_blocking(move || {
        crate::configuration::ConfigStore::new(&app.profiles).and_then(|s| s.list())
    })
    .await
    .unwrap_or(Err(crate::configuration::ConfigError::Storage))
    {
        Ok(profiles) => Json(serde_json::json!({"success":true,"profiles":profiles})).into_response(),
        Err(e) => config_error(e),
    }
}
async fn profile_get(State(app): State<App>, Path(id): Path<String>) -> Response {
    match tokio::task::spawn_blocking(move || {
        crate::configuration::ConfigStore::new(&app.profiles).and_then(|s| s.read(&id))
    })
    .await
    .unwrap_or(Err(crate::configuration::ConfigError::Storage))
    {
        Ok(p) => Json(serde_json::json!({"success":true,"profile":profile_json(p)})).into_response(),
        Err(e) => config_error(e),
    }
}
#[derive(Deserialize)]
struct SaveProfile {
    source: String,
    expected_revision: Option<String>,
}
async fn profile_put(State(app): State<App>, Path(id): Path<String>, Json(req): Json<SaveProfile>) -> Response {
    match tokio::task::spawn_blocking(move || {
        crate::configuration::ConfigStore::new(&app.profiles)
            .and_then(|s| s.save(&id, &req.source, req.expected_revision.as_deref()))
    })
    .await
    .unwrap_or(Err(crate::configuration::ConfigError::Storage))
    {
        Ok(p) => Json(serde_json::json!({"success":true,"profile":profile_json(p)})).into_response(),
        Err(e) => config_error(e),
    }
}
#[derive(Deserialize)]
struct DeleteProfile {
    expected_revision: String,
}
async fn profile_delete(State(app): State<App>, Path(id): Path<String>, Json(req): Json<DeleteProfile>) -> Response {
    match tokio::task::spawn_blocking(move || {
        crate::configuration::ConfigStore::new(&app.profiles).and_then(|s| s.delete(&id, &req.expected_revision))
    })
    .await
    .unwrap_or(Err(crate::configuration::ConfigError::Storage))
    {
        Ok(()) => Json(serde_json::json!({"success":true})).into_response(),
        Err(e) => config_error(e),
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RenameProfile {
    new_id: String,
    expected_revision: String,
}
async fn profile_rename(State(app): State<App>, Path(id): Path<String>, Json(req): Json<RenameProfile>) -> Response {
    match tokio::task::spawn_blocking(move || {
        crate::configuration::ConfigStore::new(&app.profiles).and_then(|s| {
            s.with_revision(&id, &req.expected_revision, || {
                crate::resources::copy_profile(&id, &req.new_id)
            })?
            .map_err(|_| crate::configuration::ConfigError::Storage)?;
            s.rename(&id, &req.new_id, &req.expected_revision)
        })
    })
    .await
    .unwrap_or(Err(crate::configuration::ConfigError::Storage))
    {
        Ok(profile) => Json(serde_json::json!({"success":true,"profile":profile_json(profile)})).into_response(),
        Err(error) => config_error(error),
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PrepareProfile {
    expected_revision: String,
}
async fn profile_prepare(State(app): State<App>, Path(id): Path<String>, Json(req): Json<PrepareProfile>) -> Response {
    use crate::configuration::{ConfigError, ConfigStore, PrepareError};
    let permit = match app.preparation_capacity.clone().try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => return result(StatusCode::SERVICE_UNAVAILABLE, "BUSY"),
    };
    tokio::task::spawn_blocking(move || {
        // Keep the permit inside the job even if the HTTP future is cancelled.
        let _permit = permit;
        match ConfigStore::new(&app.profiles)
            .map_err(PrepareError::from)
            .and_then(|s| s.prepare(&id, &req.expected_revision))
        {
            Ok(preparation) => Json(serde_json::json!({"success":true,"preparation":preparation})).into_response(),
            Err(PrepareError::Config(e)) => config_error(e),
            Err(PrepareError::AmbiguousYaml) => result(StatusCode::BAD_REQUEST, "AMBIGUOUS_YAML"),
            Err(PrepareError::InvalidYaml) => result(StatusCode::BAD_REQUEST, "INVALID_YAML"),
            Err(PrepareError::LimitExceeded) => result(StatusCode::PAYLOAD_TOO_LARGE, "PREPARATION_LIMIT"),
        }
    })
    .await
    .unwrap_or_else(|_| config_error(ConfigError::Storage))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProviderQuery {
    expected_revision: String,
}
async fn list_profile_providers(
    State(app): State<App>, Path(id): Path<String>, axum::extract::Query(query): axum::extract::Query<ProviderQuery>,
) -> Response {
    let permit = match app.preparation_capacity.clone().try_acquire_owned() {
        Ok(p) => p,
        Err(_) => return result(StatusCode::SERVICE_UNAVAILABLE, "BUSY"),
    };
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        // Resolve the same bounded YAML aliases/merges as Validate before assigning
        // IDs. Listing the raw template rejected anchors that Prepare had accepted.
        use crate::configuration::{ConfigStore, PrepareError};
        let prepared = match ConfigStore::new(&app.profiles)
            .map_err(PrepareError::from)
            .and_then(|s| s.prepare(&id, &query.expected_revision))
        {
            Ok(p) => p,
            Err(PrepareError::Config(e)) => return config_error(e),
            Err(PrepareError::AmbiguousYaml) => return result(StatusCode::BAD_REQUEST, "AMBIGUOUS_YAML"),
            Err(PrepareError::InvalidYaml) => return result(StatusCode::BAD_REQUEST, "INVALID_YAML"),
            Err(PrepareError::LimitExceeded) => return result(StatusCode::PAYLOAD_TOO_LARGE, "PREPARATION_LIMIT"),
        };
        match crate::mihomo::providers::list_providers(&prepared.effective_yaml) {
            Ok(providers) => {
                Json(serde_json::json!({"success":true,"revision":prepared.revision,"providers":providers}))
                    .into_response()
            }
            Err(_) => result(StatusCode::BAD_REQUEST, "INVALID"),
        }
    })
    .await
    .unwrap_or_else(|_| result(StatusCode::INTERNAL_SERVER_ERROR, "STORAGE_ERROR"))
}
pub fn app(auth: AuthState, bind: SocketAddr) -> Router {
    build_app(auth, bind, PathBuf::from("/etc/xkeenwrt/profiles"), false, None)
}
#[doc(hidden)]
pub fn app_with_profiles(auth: AuthState, bind: SocketAddr, profiles: PathBuf) -> Router {
    build_app(auth, bind, profiles, true, None)
}
pub fn app_trusted(bind: SocketAddr, profiles: PathBuf, trusted_access: crate::management::TrustedAccess) -> Router {
    build_app(AuthState::trusted(), bind, profiles, false, Some(trusted_access))
}
/// Per-listener authorities and access policies share the same bounded jobs,
/// catalog update manager and runtime request capacities.
#[derive(Clone)]
pub struct TrustedApps(App);
impl TrustedApps {
    pub fn new(profiles: PathBuf) -> Self {
        Self(app_state(
            AuthState::trusted(),
            "127.0.0.1:1000".parse().expect("fixed socket"),
            profiles,
            false,
            None,
        ))
    }
    pub fn router(&self, bind: SocketAddr, access: crate::management::TrustedAccess) -> Router {
        let mut state = self.0.clone();
        state.authority = bind.to_string();
        state.trusted_access = Some(access);
        routes(state)
    }
}
fn build_app(
    auth: AuthState, bind: SocketAddr, profiles: PathBuf, preview: bool,
    trusted_access: Option<crate::management::TrustedAccess>,
) -> Router {
    routes(app_state(auth, bind, profiles, preview, trusted_access))
}
fn app_state(
    auth: AuthState, bind: SocketAddr, profiles: PathBuf, preview: bool,
    trusted_access: Option<crate::management::TrustedAccess>,
) -> App {
    App {
        auth,
        authority: bind.to_string(),
        profiles,
        preview,
        trusted_access,
        core_updates: Arc::new(crate::core_update::Manager::new()),
        self_update: Arc::new(crate::self_update::Updater::default()),
        preparation_capacity: Arc::new(tokio::sync::Semaphore::new(1)),
        runtime_capacity: Arc::new(tokio::sync::Semaphore::new(1)),
        status_snapshot: Arc::new(snapshot::StatusSnapshot::default()),
        relay_capacity: Arc::new(tokio::sync::Semaphore::new(4)),
        websocket_capacity: Arc::new(tokio::sync::Semaphore::new(4)),
        login_capacity: Arc::new(tokio::sync::Semaphore::new(MAX_LOGIN_HASHES_IN_FLIGHT)),
    }
}
fn routes(state: App) -> Router {
    Router::new()
        .route("/api/auth/setup", post(setup))
        .route("/api/auth/login", get(login_info).post(login))
        .route("/api/auth/logout", post(logout))
        .route("/api/platform", get(platform))
        .route("/api/app-info", get(app_info))
        .route("/api/profiles", get(list_profiles))
        .route("/api/profiles/{id}/rename", post(profile_rename))
        .route(
            "/api/profiles/{id}/resources",
            get(resources_get)
                .post(resources_upload)
                .layer(DefaultBodyLimit::max(12 * 1024 * 1024)),
        )
        .route("/api/dns", get(dns_status))
        .route("/api/device-list", get(crate::device_list::get))
        .route("/api/geo", get(geo_get))
        .route("/api/geo/ip", get(geo_ip))
        .route("/api/geo/site", get(geo_site))
        .route("/api/route-test", get(route_init).post(route_run))
        .route("/api/profiles/{id}/prepare", post(profile_prepare))
        .route("/api/profiles/{id}/validate", post(validate_profile))
        .route("/api/profiles/{id}/candidate/cancel", post(cancel_profile_candidate))
        .route("/api/profiles/{id}/apply", post(apply_profile))
        .route("/api/profiles/{id}/providers", get(list_profile_providers))
        .route(
            "/api/profiles/{id}/providers/{provider_id}/refresh",
            post(refresh_profile_provider),
        )
        .route(
            "/api/profiles/{id}/providers/{provider_id}/content",
            get(provider_content).put(edit_profile_provider),
        )
        .route(
            "/api/profiles/{id}",
            get(profile_get).put(profile_put).delete(profile_delete),
        )
        .route("/api/control", get(control_status).post(control))
        .route("/api/inputs", get(inputs_status))
        .route("/api/inputs/explicit", post(explicit_set))
        .route("/api/system", get(system_status))
        .route(
            "/api/backup",
            get(backups_get)
                .put(backups_create)
                .post(backups_restore)
                .delete(backups_delete)
                .patch(backups_rename),
        )
        .route("/api/core/catalog", get(core_catalog))
        .route("/api/core/update", post(core_update_start))
        .route("/api/core/update/cancel", post(core_update_cancel))
        .route("/api/core/update/rollback", post(core_update_rollback))
        .route("/ws/core-update", get(core_update_ws))
        .route("/api/self/catalog", get(self_catalog))
        .route("/api/self/update", post(self_update_start))
        .route("/api/self/update/status", get(self_update_status))
        .route(
            "/api/network/plan",
            post(network_plan).layer(DefaultBodyLimit::max(4096)),
        )
        .route(
            "/api/network/apply",
            post(network_apply).layer(DefaultBodyLimit::max(4096)),
        )
        .route(
            "/api/network/confirm",
            post(network_confirm).layer(DefaultBodyLimit::max(4096)),
        )
        .route("/api/network/status", get(network_status))
        .route("/api/network/compatibility", get(network_compatibility))
        .route("/api/network/disable", post(network_disable))
        .route(
            "/api/core/{*path}",
            axum::routing::any(core_relay).layer(DefaultBodyLimit::max(16 * 1024)),
        )
        .route("/ws/core/{stream}", get(core_ws))
        .route("/ws/log", get(system_log_ws))
        .fallback(fallback)
        .layer(DefaultBodyLimit::max(2 * 1024 * 1024))
        .layer(middleware::from_fn_with_state(state.clone(), guard))
        .layer(middleware::from_fn(no_cache))
        .with_state(state)
}

async fn no_cache(req: Request, next: Next) -> Response {
    let api = req.uri().path().starts_with("/api/");
    let mut response = next.run(req).await;
    if api {
        response
            .headers_mut()
            .insert(header::CACHE_CONTROL, axum::http::HeaderValue::from_static("no-store"));
    }
    response
}

#[cfg(test)]
mod resume_http_contract_tests {
    use super::*;

    #[test]
    fn platform_exposes_only_capabilities_reported_by_one_runtime_status() {
        use crate::runtime::RuntimeCapability as Capability;
        let mut info = crate::platform::PlatformInfo {
            platform: "openwrt",
            core: "mihomo",
            capabilities: vec!["platform_inspect"],
            unsupported_reasons: vec!["Managed configuration validation and network recovery are not ready"],
        };
        expose_runtime_capabilities(
            &mut info,
            Some(&[
                Capability::CoreControl,
                Capability::ProfileValidate,
                Capability::ProfileApplyManual,
                Capability::CoreRelay,
                Capability::ProviderRefresh,
                Capability::NetworkIntegration,
            ]),
        );
        assert_eq!(
            info.capabilities,
            vec![
                "platform_inspect",
                "core_control",
                "profile_validate",
                "profile_apply_manual",
                "core_relay",
                "provider_refresh",
                "network_integration",
            ]
        );
        assert!(info.unsupported_reasons.is_empty());

        let mut mismatch = crate::platform::PlatformInfo {
            platform: "openwrt",
            core: "mihomo",
            capabilities: vec!["platform_inspect"],
            unsupported_reasons: vec!["Managed configuration validation and network recovery are not ready"],
        };
        expose_runtime_capabilities(&mut mismatch, Some(&[Capability::CoreControl]));
        assert_eq!(mismatch.capabilities, vec!["platform_inspect", "core_control"]);
        assert_eq!(mismatch.unsupported_reasons.len(), 5);

        let mut unavailable = crate::platform::PlatformInfo {
            platform: "openwrt",
            core: "mihomo",
            capabilities: vec!["platform_inspect"],
            unsupported_reasons: vec![],
        };
        expose_runtime_capabilities(&mut unavailable, None);
        assert_eq!(unavailable.capabilities, vec!["platform_inspect"]);
        assert_eq!(
            unavailable.unsupported_reasons,
            vec!["Native runtime status is unavailable"]
        );
    }

    #[test]
    fn authenticated_control_body_maps_only_explicit_resume_request_id() {
        let request_id = "00000000-0000-4000-8000-000000000002";
        let request: ControlRequest = serde_json::from_value(serde_json::json!({
            "action": "resume_after_reinstall",
            "request_id": request_id,
        }))
        .unwrap();
        let command = request.into_command().unwrap();
        assert_eq!(
            serde_json::to_value(command).unwrap(),
            serde_json::json!({"command":"resume_after_reinstall","request_id":request_id})
        );
        assert!(
            serde_json::from_value::<ControlRequest>(serde_json::json!({
                "action": "resume_after_reinstall"
            }))
            .unwrap()
            .into_command()
            .is_none()
        );
        assert!(
            serde_json::from_value::<ControlRequest>(serde_json::json!({
                "action": "resume_after_reinstall",
                "request_id": request_id,
                "path": "/etc/xkeenwrt/removal.json"
            }))
            .is_err()
        );
    }

    #[test]
    fn restart_is_separate_from_start_stop_and_rejects_legacy_actions() {
        let restart: ControlRequest = serde_json::from_value(serde_json::json!({"action":"restart"})).unwrap();
        assert_eq!(
            serde_json::to_value(restart.into_command().unwrap()).unwrap(),
            serde_json::json!({"command":"restart"})
        );
        let legacy: ControlRequest = serde_json::from_value(serde_json::json!({"action":"hardRestart"})).unwrap();
        assert!(legacy.into_command().is_none());
    }

    #[tokio::test]
    async fn successful_resume_http_reply_confirms_core_is_stopped() {
        let mut reply = crate::runtime::RuntimeReply::error("OK", "resumed_stopped");
        reply.running = Some(false);
        let response = runtime_success_response(reply, true);
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 1024).await.unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&body).unwrap(),
            serde_json::json!({"success":true,"running":false})
        );

        let missing_state =
            runtime_success_response(crate::runtime::RuntimeReply::error("OK", "resumed_stopped"), true);
        assert_eq!(missing_state.status(), StatusCode::SERVICE_UNAVAILABLE);
    }
}

#[cfg(test)]
mod overlay_stream_tests {
    #[tokio::test(start_paused = true)]
    async fn revoking_overlay_closes_an_idle_upgraded_stream_and_releases_its_capacity() {
        use std::sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        };
        let current = Arc::new(AtomicBool::new(true));
        let checked = current.clone();
        let capacity = Arc::new(tokio::sync::Semaphore::new(1));
        let permit = capacity.clone().acquire_owned().await.unwrap();
        let task = tokio::spawn(super::scoped_stream_until(
            move || checked.load(Ordering::SeqCst),
            async move {
                let _permit = permit;
                std::future::pending::<()>().await;
            },
        ));
        tokio::task::yield_now().await;
        assert!(!task.is_finished());
        current.store(false, Ordering::SeqCst);
        tokio::time::advance(std::time::Duration::from_secs(1)).await;
        task.await.unwrap();
        assert!(capacity.try_acquire_owned().is_ok());
    }
}

#[cfg(test)]
mod runtime_error_tests {
    use super::*;

    #[tokio::test]
    async fn refused_remote_confirmation_keeps_its_text_and_probe_report() {
        let mut reply = crate::runtime::RuntimeReply::error(
            "NETWORK_REMOTE_EGRESS",
            "Ни один прокси не ответил на проверку выхода. Перехват не подтверждён и будет снят.",
        );
        reply.network = Some(serde_json::json!({"remote_check":{
            "dns":true,"egress":{"state":"failed","tested":1},"lan_clients":0}}));
        let response = runtime_error_response(reply);
        assert_eq!(response.status(), StatusCode::CONFLICT);
        let body = axum::body::to_bytes(response.into_body(), 8192).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["code"], "NETWORK_REMOTE_EGRESS");
        assert!(v["error"].as_str().unwrap().contains("прокси"));
        assert_eq!(v["network"]["remote_check"]["egress"]["state"], "failed");
    }

    #[tokio::test]
    async fn other_runtime_errors_keep_their_bounded_shape() {
        let response = runtime_error_response(crate::runtime::RuntimeReply::error("BUSY", "internal detail"));
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = axum::body::to_bytes(response.into_body(), 8192).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["code"], "BUSY");
        assert!(v.get("network").is_none());
        assert!(!body.windows(15).any(|w| w == b"internal detail"));
    }
}
