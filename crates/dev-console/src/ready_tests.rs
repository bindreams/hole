use crate::ready::{wait_for_port, ReadyListener};

#[skuld::test]
async fn ready_listener_accepts_matching_token() {
    let listener = ReadyListener::bind().await.unwrap();
    let spec = listener.notify_arg();
    // Simulate the bridge side exactly (connect + token line + close).
    let client = tokio::spawn(async move {
        use tokio::io::AsyncWriteExt as _;
        let (addr, token) = spec.rsplit_once('/').unwrap();
        let mut conn = tokio::net::TcpStream::connect(addr).await.unwrap();
        conn.write_all(format!("{token}\n").as_bytes()).await.unwrap();
    });
    listener.wait().await.expect("token accepted");
    client.await.unwrap();
}

#[skuld::test]
async fn ready_listener_ignores_wrong_token_and_keeps_waiting() {
    let listener = ReadyListener::bind().await.unwrap();
    let spec = listener.notify_arg();
    let client = tokio::spawn(async move {
        use tokio::io::AsyncWriteExt as _;
        let (addr, token) = spec.rsplit_once('/').unwrap();
        let mut bogus = tokio::net::TcpStream::connect(addr).await.unwrap();
        bogus.write_all(b"wrong-token\n").await.unwrap();
        drop(bogus);
        let mut good = tokio::net::TcpStream::connect(addr).await.unwrap();
        good.write_all(format!("{token}\n").as_bytes()).await.unwrap();
    });
    listener.wait().await.expect("eventually the right token");
    client.await.unwrap();
}

/// THE load-bearing JoinSet property: an open-but-silent connection must not
/// wedge the wait. A serial accept→read design hangs here (the mute conn is
/// queued first and never sends); the per-connection-task design resolves on
/// the real token regardless. Bounded by the per-test timeout (class-2).
#[skuld::test]
async fn ready_listener_survives_a_mute_connection() {
    let listener = ReadyListener::bind().await.unwrap();
    let spec = listener.notify_arg();
    let (addr, token) = spec.rsplit_once('/').unwrap();
    let addr = addr.to_string();
    let token = token.to_string();
    // Mute conn FIRST (queued ahead in the backlog), held open for the whole
    // test — never writes a byte.
    let mute = tokio::net::TcpStream::connect(&addr).await.unwrap();
    let client = tokio::spawn(async move {
        use tokio::io::AsyncWriteExt as _;
        let mut good = tokio::net::TcpStream::connect(&addr).await.unwrap();
        good.write_all(format!("{token}\n").as_bytes()).await.unwrap();
    });
    listener.wait().await.expect("token must win despite the mute conn");
    drop(mute);
    client.await.unwrap();
}

#[skuld::test]
async fn port_probe_finds_v4_listener() {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    assert!(wait_for_port(port, std::time::Duration::from_secs(5)).await);
}

/// The v6-only case dev.py §5.5 guards: a listener on ::1 only must still be
/// found (hosts-file ordering can make Vite's `localhost` bind v6-only).
/// Loud-fail by design if ::1 is unavailable — all six GitHub-hosted runner
/// images have IPv6 loopback; a runner without it should break this test,
/// not skip it.
#[skuld::test]
async fn port_probe_finds_v6_only_listener() {
    let Ok(l) = std::net::TcpListener::bind("[::1]:0") else {
        panic!("IPv6 loopback unavailable on this host — the v6 probe path needs a v6-capable machine");
    };
    let port = l.local_addr().unwrap().port();
    assert!(wait_for_port(port, std::time::Duration::from_secs(5)).await);
}

/// Deterministic timeout path: port 0 is never connectable (the kernel
/// rejects connect-to-port-0 outright), so no "did someone rebind my
/// released port" race; paused virtual time makes the budget elapse
/// instantly (skuld async = current-thread runtime, tokio auto-advance).
#[skuld::test]
async fn port_probe_times_out_when_nothing_listens() {
    tokio::time::pause();
    assert!(!wait_for_port(0, std::time::Duration::from_secs(3)).await);
}

#[skuld::test]
async fn port_in_use_is_a_single_probe_round() {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    assert!(crate::ready::port_in_use(port).await);
    // Port 0: nothing can listen there — one round, returns false fast.
    assert!(!crate::ready::port_in_use(0).await);
}
