use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use tower::ServiceExt;
use xkeen_ui::http::{AuthState, app};

#[tokio::test]
async fn unauthenticated_mutation_is_401() {
    let app = app(AuthState::for_test("bootstrap"), "127.0.0.1:1080".parse().unwrap());
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/control")
                .header("host", "127.0.0.1:1080")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(response.headers().get("cache-control").unwrap(), "no-store");
}

#[tokio::test]
async fn login_attempts_are_reserved_per_source_before_password_verification() {
    let app = app(AuthState::for_test("bootstrap"), "127.0.0.1:1080".parse().unwrap());
    let setup = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/auth/setup")
                .header("host", "127.0.0.1:1080")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"password":"long enough password","token":"bootstrap"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(setup.status(), StatusCode::OK);
    let login = |peer: &str, password: &str| {
        Request::builder()
            .method("POST")
            .uri("/api/auth/login")
            .header("host", "127.0.0.1:1080")
            .header("content-type", "application/json")
            .extension(axum::extract::ConnectInfo(
                peer.parse::<std::net::SocketAddr>().unwrap(),
            ))
            .body(Body::from(format!("{{\"password\":\"{password}\"}}")))
            .unwrap()
    };
    for _ in 0..5 {
        let reply = app
            .clone()
            .oneshot(login("192.0.2.1:41000", "incorrect password"))
            .await
            .unwrap();
        assert_eq!(reply.status(), StatusCode::UNAUTHORIZED);
    }
    let limited = app
        .clone()
        .oneshot(login("192.0.2.1:41001", "long enough password"))
        .await
        .unwrap();
    assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);
    let other_source = app
        .oneshot(login("192.0.2.2:41000", "long enough password"))
        .await
        .unwrap();
    assert_eq!(other_source.status(), StatusCode::OK);
}

#[tokio::test]
async fn foreign_origin_ws_is_rejected() {
    let app = app(AuthState::for_test("bootstrap"), "127.0.0.1:1080".parse().unwrap());
    let response = app
        .oneshot(
            Request::builder()
                .uri("/ws/log")
                .header("host", "127.0.0.1:1080")
                .header("origin", "http://evil.example")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn bootstrap_cannot_be_claimed_without_token() {
    let app = app(AuthState::for_test("bootstrap"), "127.0.0.1:1080".parse().unwrap());
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/auth/setup")
                .header("host", "127.0.0.1:1080")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"password":"long enough password"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn bootstrap_token_creates_session_and_cannot_be_reused() {
    let app = app(AuthState::for_test("bootstrap"), "127.0.0.1:1080".parse().unwrap());
    let request = || {
        Request::builder()
            .method("POST")
            .uri("/api/auth/setup")
            .header("host", "127.0.0.1:1080")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"password":"long enough password","token":"bootstrap"}"#))
            .unwrap()
    };
    let response = app.clone().oneshot(request()).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let cookie = response
        .headers()
        .get("set-cookie")
        .unwrap()
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/platform")
                .header("host", "127.0.0.1:1080")
                .header("cookie", cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(app.oneshot(request()).await.unwrap().status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn authenticated_profile_can_be_saved_and_conflict_is_reported() {
    use xkeen_ui::http::app_with_profiles;
    let root = std::env::temp_dir().join(format!("xkeenwrt-http-test-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&root).unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let app = app_with_profiles(
        AuthState::for_test("bootstrap"),
        "127.0.0.1:1000".parse().unwrap(),
        root.clone(),
    );
    let auth = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/auth/setup")
                .header("host", "127.0.0.1:1000")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"password":"long enough password","token":"bootstrap"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    let cookie = auth
        .headers()
        .get("set-cookie")
        .unwrap()
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();
    let save = || {
        Request::builder()
            .method("PUT")
            .uri("/api/profiles/demo")
            .header("host", "127.0.0.1:1000")
            .header("cookie", &cookie)
            .header("content-type", "application/json")
            .body(Body::from(r#"{"source":"proxies: []\n","expected_revision":null}"#))
            .unwrap()
    };
    assert_eq!(app.clone().oneshot(save()).await.unwrap().status(), StatusCode::OK);
    assert_eq!(
        app.clone().oneshot(save()).await.unwrap().status(),
        StatusCode::CONFLICT
    );
    assert_eq!(
        app.oneshot(
            Request::builder()
                .uri("/api/profiles/demo")
                .header("host", "127.0.0.1:1000")
                .header("cookie", cookie)
                .body(Body::empty())
                .unwrap()
        )
        .await
        .unwrap()
        .status(),
        StatusCode::OK
    );
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn password_survives_restart_and_corrupt_hash_is_rejected() {
    let root = std::env::temp_dir().join(format!("xkeenwrt-auth-test-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&root).unwrap();
    let path = root.join("password-hash");
    let app = app(
        AuthState::new("bootstrap".into(), path.clone()).unwrap(),
        "127.0.0.1:1000".parse().unwrap(),
    );
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/auth/setup")
                .header("host", "127.0.0.1:1000")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"password":"long enough password","token":"bootstrap"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let restarted = xkeen_ui::http::app(
        AuthState::new("bootstrap".into(), path.clone()).unwrap(),
        "127.0.0.1:1000".parse().unwrap(),
    );
    let response = restarted
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/auth/login")
                .header("host", "127.0.0.1:1000")
                .extension(axum::extract::ConnectInfo(
                    "192.0.2.10:41000".parse::<std::net::SocketAddr>().unwrap(),
                ))
                .header("content-type", "application/json")
                .body(Body::from(r#"{"password":"long enough password"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    std::fs::write(&path, "$argon2id$partial").unwrap();
    assert!(AuthState::new("bootstrap".into(), path).is_err());
    std::fs::remove_dir_all(root).unwrap();
}
