use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use tower::ServiceExt;
use xkeen_ui::{
    configuration::ConfigStore,
    http::{AuthState, app_with_profiles},
};
#[tokio::test]
async fn preparation_requires_auth_and_returns_no_store_preview() {
    let root = std::env::temp_dir().join(format!("prepare-http-{}", uuid::Uuid::new_v4()));
    let store = ConfigStore::new(&root).unwrap();
    let saved = store.save("home", "mode: rule\n", None).unwrap();
    let app = app_with_profiles(
        AuthState::for_test("bootstrap"),
        "127.0.0.1:1080".parse().unwrap(),
        root.clone(),
    );
    let request = |cookie: &str| {
        Request::builder()
            .method("POST")
            .uri("/api/profiles/home/prepare")
            .header("host", "127.0.0.1:1080")
            .header("cookie", cookie)
            .header("content-type", "application/json")
            .body(Body::from(format!("{{\"expected_revision\":\"{}\"}}", saved.revision)))
            .unwrap()
    };
    let no_auth = app.clone().oneshot(request("")).await.unwrap();
    assert_eq!(no_auth.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(no_auth.headers()["cache-control"], "no-store");
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
    let cookie = setup.headers()["set-cookie"]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap();
    for (body, status) in [
        (r#"{"expected_revision":"stale"}"#, StatusCode::CONFLICT),
        (
            r#"{"expected_revision":"stale","source":"mode: direct"}"#,
            StatusCode::UNPROCESSABLE_ENTITY,
        ),
        (r#"{}"#, StatusCode::UNPROCESSABLE_ENTITY),
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/profiles/home/prepare")
                    .header("host", "127.0.0.1:1080")
                    .header("cookie", cookie)
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), status);
        assert_eq!(response.headers()["cache-control"], "no-store");
    }
    let reply = app.oneshot(request(cookie)).await.unwrap();
    assert_eq!(reply.status(), StatusCode::OK);
    assert_eq!(reply.headers()["cache-control"], "no-store");
    let json: serde_json::Value =
        serde_json::from_slice(&to_bytes(reply.into_body(), 1024 * 1024).await.unwrap()).unwrap();
    assert_eq!(json["preparation"]["core_validation"], "not_run");
    assert_eq!(json["preparation"]["activatable"], false);
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_preparation_is_rejected_when_capacity_is_in_use() {
    let root = std::env::temp_dir().join(format!("prepare-http-{}", uuid::Uuid::new_v4()));
    let store = ConfigStore::new(&root).unwrap();
    let source = format!("rules: [{}]\n", "entry,".repeat(45_000));
    let saved = store.save("home", &source, None).unwrap();
    let app = app_with_profiles(
        AuthState::for_test("bootstrap"),
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
                .body(Body::from(r#"{"password":"long enough password","token":"bootstrap"}"#))
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
    let request = || {
        Request::builder()
            .method("POST")
            .uri("/api/profiles/home/prepare")
            .header("host", "127.0.0.1:1080")
            .header("cookie", &cookie)
            .header("content-type", "application/json")
            .body(Body::from(format!("{{\"expected_revision\":\"{}\"}}", saved.revision)))
            .unwrap()
    };
    let (a, b) = tokio::join!(app.clone().oneshot(request()), app.oneshot(request()));
    let statuses = [a.unwrap().status(), b.unwrap().status()];
    assert!(statuses.contains(&StatusCode::OK));
    assert!(statuses.contains(&StatusCode::SERVICE_UNAVAILABLE));
    std::fs::remove_dir_all(root).unwrap();
}
