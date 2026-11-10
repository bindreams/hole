use super::*;
use hole_common::protocol::Refusal;

fn state_blocked() -> Refusal {
    Refusal::StateBlocked {
        files: vec!["bridge-routes.json".into()],
    }
}

/// A reload refused over unreadable state files reads as the start's refusal, and says the session is stopped.
#[skuld::test]
fn a_refused_reload_renders_its_refusal_and_says_the_proxy_stopped() {
    let toast = reload_error_toast(ReloadError::Refused(state_blocked()));
    assert!(toast.contains(&start_error_toast(&state_blocked())), "{toast}");
    assert!(toast.contains("did not come back up"), "{toast}");
}

/// A reload with no answer does not say the proxy stopped: it is not known.
#[skuld::test]
fn an_unanswered_reload_does_not_claim_the_proxy_stopped() {
    let toast = reload_error_toast(ReloadError::Transport);
    assert!(toast.contains("may not have been applied"), "{toast}");
    assert!(!toast.contains("did not come back up"), "{toast}");
}

/// A reload the bridge answered and rejected was not acted on: the toast says it was not applied, not that it may
/// not have been, and not that the proxy stopped.
#[skuld::test]
fn a_rejected_reload_says_it_was_not_applied() {
    let toast = reload_error_toast(ReloadError::Rejected);
    assert!(toast.contains("rejected"), "{toast}");
    assert!(toast.contains("was not applied"), "{toast}");
    assert!(!toast.contains("may not have been applied"), "{toast}");
    assert!(!toast.contains("did not come back up"), "{toast}");
}

/// `start_error_toast` renders each refusal; host-free ones are shown raw, a failure is wrapped.
#[skuld::test]
fn each_refusal_has_its_toast() {
    assert_eq!(
        start_error_toast(&Refusal::NetworkBlocked),
        hole_common::protocol::NETWORK_BLOCKED_MESSAGE
    );
    assert_eq!(
        start_error_toast(&Refusal::Failed {
            message: "plugin failed".into()
        }),
        "Bridge error: plugin failed"
    );
    let toast = start_error_toast(&state_blocked());
    assert!(toast.contains("bridge-routes.json"), "{toast}");
    assert!(toast.contains("Help > Reset Network…"), "{toast}");
}

/// The policy of a [`StartError`] lives on the type (`leaves_session_up`, `reload_refusal`): a call site that picks out
/// one variant with `matches!`, `if let`, `let ... else` or a comparison re-derives it, and a new variant would not make
/// it choose. A `match` that lists every variant is checked by the compiler and is fine.
#[skuld::test]
fn no_call_site_picks_out_a_start_error_variant() {
    let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let variant = r"StartError::(Cancelled|AlreadyRunning|Refused)\b";
    let picks = regex::Regex::new(&format!(
        r"matches!\(.*{variant}|\b(if|while) let .*{variant}|\blet .*{variant}.* else\b|[!=]=\s*&?{variant}"
    ))
    .unwrap();
    let mut offenders = Vec::new();
    for entry in walkdir::WalkDir::new(&src) {
        let entry = entry.expect("failed to walk crates/hole/src");
        let path = entry.path();
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if !name.ends_with(".rs") || name.ends_with("_tests.rs") {
            continue;
        }
        let text = std::fs::read_to_string(path).expect("failed to read a source file");
        for (idx, line) in text.lines().enumerate() {
            let code = line.trim_start();
            if !code.starts_with("//") && picks.is_match(code) {
                offenders.push(format!("{}:{}: {code}", path.display(), idx + 1));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "StartError variants picked out outside tests:\n  {}\nAdd the question to `StartError` or match every variant.",
        offenders.join("\n  ")
    );
}
