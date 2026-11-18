use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use tower::ServiceExt;
use xkeen_ui::http::{AuthState, app_with_profiles};

#[tokio::test]
async fn runtime_mutations_require_auth_and_preview_is_inert() {
    let root = std::env::temp_dir().join(format!("xkeen-http-{}", uuid::Uuid::new_v4()));
    let app = app_with_profiles(
        AuthState::for_test("test-token"),
        "127.0.0.1:1080".parse().unwrap(),
        root.clone(),
    );
    let request = |path: &str, body: &str, cookie: &str| {
        Request::builder()
            .method("POST")
            .uri(path)
            .header("host", "127.0.0.1:1080")
            .header("cookie", cookie)
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap()
    };
    assert_eq!(
        app.clone()
            .oneshot(request(
                "/api/profiles/home/validate",
                r#"{"expected_revision":"r"}"#,
                ""
            ))
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        app.clone()
            .oneshot(request(
                "/api/profiles/home/candidate/cancel",
                r#"{"expected_revision":"r","candidate_id":"candidate"}"#,
                "",
            ))
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    let setup = app
        .clone()
        .oneshot(request(
            "/api/auth/setup",
            r#"{"password":"long enough password","token":"test-token"}"#,
            "",
        ))
        .await
        .unwrap();
    let cookie = setup.headers()["set-cookie"]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();
    let cancelled = app
        .clone()
        .oneshot(request(
            "/api/profiles/home/candidate/cancel",
            r#"{"expected_revision":"r","candidate_id":"candidate"}"#,
            &cookie,
        ))
        .await
        .unwrap();
    assert_eq!(cancelled.status(), StatusCode::SERVICE_UNAVAILABLE);
    let reply = app
        .oneshot(request(
            "/api/profiles/home/validate",
            r#"{"expected_revision":"r"}"#,
            &cookie,
        ))
        .await
        .unwrap();
    assert_eq!(reply.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(reply.headers()["cache-control"], "no-store");
    assert!(!root.exists());
}

#[tokio::test]
async fn provider_list_is_revision_checked_and_hides_subscription_url() {
    use axum::body::to_bytes;
    use xkeen_ui::configuration::ConfigStore;
    let root = std::env::temp_dir().join(format!("xkeen-http-{}", uuid::Uuid::new_v4()));
    let store = ConfigStore::new(&root).unwrap();
    let saved = store
        .save(
            "home",
            "anchors: {http: &http {type: http}}\nproxy-providers:\n  demo: {<<: *http, url: https://example.invalid/secret}\nrule-providers:\n  domains: {<<: *http, url: https://example.invalid/rules, behavior: domain}\n",
            None,
        )
        .unwrap();
    let app = app_with_profiles(
        AuthState::for_test("token"),
        "127.0.0.1:1080".parse().unwrap(),
        root.clone(),
    );
    let setup = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/auth/setup")
                .header("host", "127.0.0.1:1080")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"password":"long enough password","token":"token"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    let cookie = setup.headers()["set-cookie"]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();
    let get = |revision: &str| {
        Request::builder()
            .uri(format!("/api/profiles/home/providers?expected_revision={revision}"))
            .header("host", "127.0.0.1:1080")
            .header("cookie", &cookie)
            .body(Body::empty())
            .unwrap()
    };
    let stale = app.clone().oneshot(get("stale")).await.unwrap();
    assert_eq!(stale.status(), StatusCode::CONFLICT);
    let response = app.oneshot(get(&saved.revision)).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = to_bytes(response.into_body(), 8192).await.unwrap();
    let text = std::str::from_utf8(&bytes).unwrap();
    assert!(text.contains("proxy-0") && text.contains("rule-0"));
    assert!(!text.contains("example.invalid"));
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn network_plan_uses_transport_peer_instead_of_claimed_management_address() {
    use axum::extract::ConnectInfo;
    let root = std::env::temp_dir().join(format!("xkeen-http-{}", uuid::Uuid::new_v4()));
    let app = app_with_profiles(AuthState::for_test("token"), "127.0.0.1:1080".parse().unwrap(), root);
    let setup = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/auth/setup")
                .header("host", "127.0.0.1:1080")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"password":"long enough password","token":"token"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    let cookie = setup.headers()["set-cookie"]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();
    let body = r#"{"profile_id":"home","expected_revision":"r","candidate_id":"c","lan_interface":"br-lan","selected_ipv4":"192.0.2.7","management_ipv4":"192.0.2.8","selected_ipv6":[],"management_ipv6":[],"ipv6_policy":"block_external","failure_policy":"direct_on_failure"}"#;
    let request = Request::builder()
        .method("POST")
        .uri("/api/network/plan")
        .header("host", "127.0.0.1:1080")
        .header("cookie", cookie)
        .header("content-type", "application/json")
        .extension(ConnectInfo::<std::net::SocketAddr>("192.0.2.9:31000".parse().unwrap()))
        .body(Body::from(body))
        .unwrap();
    assert_eq!(app.oneshot(request).await.unwrap().status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn panel_self_update_requires_auth_and_preview_is_inert() {
    let root = std::env::temp_dir().join(format!("xkeen-http-{}", uuid::Uuid::new_v4()));
    let app = app_with_profiles(
        AuthState::for_test("token"),
        "127.0.0.1:1080".parse().unwrap(),
        root.clone(),
    );
    let call = |method: &str, path: &str, cookie: &str| {
        Request::builder()
            .method(method)
            .uri(path)
            .header("host", "127.0.0.1:1080")
            .header("cookie", cookie)
            .header("content-type", "application/json")
            .body(Body::from(if method == "POST" { r#"{"version":"9.9.9"}"# } else { "" }))
            .unwrap()
    };
    let endpoints = [
        ("GET", "/api/self/catalog"),
        ("POST", "/api/self/update"),
        ("GET", "/api/self/update/status"),
    ];
    for (method, path) in endpoints {
        let reply = app.clone().oneshot(call(method, path, "")).await.unwrap();
        assert_eq!(reply.status(), StatusCode::UNAUTHORIZED, "{path}");
    }
    let setup = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/auth/setup")
                .header("host", "127.0.0.1:1080")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"password":"long enough password","token":"token"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    let cookie = setup.headers()["set-cookie"]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();
    for (method, path) in endpoints {
        let reply = app.clone().oneshot(call(method, path, &cookie)).await.unwrap();
        assert_eq!(reply.status(), StatusCode::SERVICE_UNAVAILABLE, "{path}");
    }
    assert!(!std::path::Path::new(xkeen_ui::self_update::WORK_DIR).exists());
}
