//! `cargo xtask sign-static`: sign `static/hole.yaml` in place.
//!
//! The file is a signed envelope (see [`hole_common::withdrawals`]). The maintainer edits the `payload` and
//! this signs it, exactly as the client will read it back: each signature covers the string the YAML parser
//! returns for `payload`, so the rewritten file must hand the same string back. A key rotation signs with
//! the old and the new key, one signature per key.

#![allow(clippy::disallowed_methods)] // dev tooling, never privileged

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context, Result};
use hole_common::verify::{verify_minisig_data, MINISIGN_PUBLIC_KEY};
use hole_common::withdrawals::{
    parse_envelope, parse_payload, parse_signed_with_key, Envelope, Withdrawals, ENTRY_KEYS, PAYLOAD_KEYS, PLATFORM_IDS,
};
use yaml_serde::Value;

const LIST_PATH: &str = "static/hole.yaml";

/// The trusted comment every signature carries. Minisign's default one holds a TAB, which makes the YAML
/// emitter quote the whole signature instead of writing a block.
const TRUSTED_COMMENT: &str = "hole withdrawal list static/hole.yaml";

/// Sign `static/hole.yaml` under `repo_root` with the `minisign` program: once with each of `secret_keys` in
/// order, or once with its default key when there are none, as `scripts/sign-release.py` does.
/// `public_keys` are the public halves of the keys a client may hold besides the one this tree ships (the
/// retiring key, in a rotation): the tool proves every signature against them.
pub fn run(repo_root: &Path, secret_keys: &[PathBuf], public_keys: &[String]) -> Result<()> {
    run_with(
        &repo_root.join(LIST_PATH),
        secret_keys,
        MINISIGN_PUBLIC_KEY,
        public_keys,
        &|key, payload| minisign(payload, key),
    )?;
    println!("xtask: signed {LIST_PATH}");
    Ok(())
}

/// [`run`] on the file at `path`, with the key the tree ships (`tree_key`) and the signing as parameters:
/// `sign` takes a secret key (`None` for the default one) and the payload text and returns the text of the
/// `.minisig` file.
///
/// Nothing is signed unless the payload reads as a withdrawal list and says what a maintainer means, and
/// nothing is written unless the new file hands back the same payload string and [`prove_signatures`]
/// proves the signatures. See "What the tool proves" in `docs/contributing/maintainers/withdrawal-list.md`.
pub(crate) fn run_with(
    path: &Path,
    secret_keys: &[PathBuf],
    tree_key: &str,
    public_keys: &[String],
    sign: &dyn Fn(Option<&Path>, &str) -> Result<String>,
) -> Result<()> {
    if secret_keys.len() > 1 && public_keys.is_empty() {
        bail!(
            "{} secret keys were given but no `--public-key`: the signature of a key the tree does not ship \
             cannot be proved, and a wrong old secret key would write a file every older client rejects; \
             pass the other key's public half (the base64 string, as `MINISIGN_PUBLIC_KEY` holds it) with \
             `--public-key`, once per key",
            secret_keys.len()
        );
    }

    let text = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let payload = parse_envelope(&text)
        .with_context(|| {
            format!(
                "{} is not an envelope with a `payload` and `signatures`",
                path.display()
            )
        })?
        .payload;
    let list = parse_payload(&payload).context("the payload is not a list a client can read, so it is not signed")?;
    check_raw_payload(&payload, &list)?;

    // `minisign` writes CRLF on Windows; verification reads the signature line by line, so LF is as good.
    let sign_one = |key: Option<&Path>| -> Result<String> { Ok(sign(key, &payload)?.replace("\r\n", "\n")) };
    let signatures = if secret_keys.is_empty() {
        vec![sign_one(None)?]
    } else {
        secret_keys
            .iter()
            .map(|key| sign_one(Some(key)))
            .collect::<Result<_>>()?
    };
    let envelope = Envelope {
        payload: payload.clone(),
        signatures,
    };
    let rendered = envelope.render().context("rendering the signed file")?;
    let untouched = format!("{} is untouched", path.display());

    let reread = parse_envelope(&rendered).context("the signed file does not parse back")?;
    if reread != envelope {
        bail!("the signed file would not hand back the payload that was signed; {untouched}");
    }
    if let Err(e) = parse_signed_with_key(&rendered, tree_key) {
        let context = if e.is_signature_failure() {
            format!(
                "none of the signatures verifies under the public key this tree ships ({tree_key}); the usual \
                 cause is a secret key other than the release key; {untouched}"
            )
        } else {
            format!("a client cannot read the signed file; {untouched}")
        };
        return Err(anyhow::Error::new(e).context(context));
    }
    prove_signatures(&payload, &envelope.signatures, secret_keys, tree_key, public_keys)
        .with_context(|| untouched.clone())?;
    std::fs::write(path, rendered).with_context(|| format!("writing {}", path.display()))
}

/// Prove every signature in `signatures` (one per secret key, in order) against the keys a client may hold:
/// each verifies under `tree_key` or one of `public_keys`, and each of those keys verifies at least one.
fn prove_signatures(
    payload: &str,
    signatures: &[String],
    secret_keys: &[PathBuf],
    tree_key: &str,
    public_keys: &[String],
) -> Result<()> {
    let verifies = |signature: &str, key: &str| verify_minisig_data(payload.as_bytes(), signature, key);
    let known = || std::iter::once(tree_key).chain(public_keys.iter().map(String::as_str));

    for (index, signature) in signatures.iter().enumerate() {
        if known().any(|key| verifies(signature, key).is_ok()) {
            continue;
        }
        let made_with = secret_keys
            .get(index)
            .map_or("minisign's default key".to_owned(), |key| key.display().to_string());
        bail!(
            "signature {} (made with {made_with}) verifies under neither the public key this tree ships nor \
             any `--public-key`; a client would reject it, and the usual cause is the wrong secret key",
            index + 1
        );
    }
    for key in known() {
        if signatures.iter().any(|signature| verifies(signature, key).is_ok()) {
            continue;
        }
        let first = signatures.first().and_then(|signature| verifies(signature, key).err());
        let why = first.map_or(String::new(), |e| format!(" ({e})"));
        bail!(
            "the public key {key} verifies none of the signatures{why}; it is either not the public half of a \
             key that signed, or not a minisign public key"
        );
    }
    Ok(())
}

/// Refuse what a client reads but a maintainer cannot have meant, walking the payload as written. A key
/// the client does not know: it ignores it, so a misspelled `platforms` or `reason` is read as absent. A
/// `platforms` with an id that is not a release platform, an empty list (covers nothing) or no value (a
/// client reads it as every platform; to withdraw on every platform the key is left out).
fn check_raw_payload(payload: &str, list: &Withdrawals) -> Result<()> {
    let raw: Value = yaml_serde::from_str(payload).context("reading the payload")?;
    check_keys(&raw, PAYLOAD_KEYS, "the payload")?;
    let raw_entries = raw.get("withdrawn").and_then(Value::as_sequence);
    for (index, entry) in list.entries().iter().enumerate() {
        let version = &entry.version;
        // `list` was parsed from this payload, so each of its entries is a raw entry at the same index.
        let raw_entry = raw_entries.and_then(|entries| entries.get(index)).with_context(|| {
            format!(
                "{version}: the payload has no `withdrawn` entry {} to check, though the client's parse read \
                     one; this is a bug in sign-static",
                index + 1
            )
        })?;
        check_keys(raw_entry, ENTRY_KEYS, &version.to_string())?;
        let blank = raw_entry.get("platforms").is_some_and(Value::is_null);
        if blank {
            bail!(
                "{version}: `platforms` has no value, which a client reads as every platform; leave the key out \
                 to withdraw on every platform"
            );
        }
        let Some(ids) = &entry.platforms else { continue };
        if ids.is_empty() {
            bail!(
                "{version}: `platforms` is empty, so it covers nothing; leave the key out to withdraw on every \
                 platform"
            );
        }
        if let Some(unknown) = ids.iter().find(|id| !PLATFORM_IDS.contains(&id.as_str())) {
            bail!(
                "{version}: `platforms` names {unknown:?}, which is not a release platform ({})",
                PLATFORM_IDS.join(", ")
            );
        }
    }
    Ok(())
}

/// Refuse a key of the mapping `value` that is not in `known`; `place` says where it was found.
fn check_keys(value: &Value, known: &[&str], place: &str) -> Result<()> {
    let Some(mapping) = value.as_mapping() else {
        bail!("{place}: is not a mapping, though the client's parse read it as one; this is a bug in sign-static");
    };
    for key in mapping.keys() {
        match key.as_str() {
            Some(name) if known.contains(&name) => {}
            _ => {
                let shown = key.as_str().map_or_else(|| format!("{key:?}"), str::to_owned);
                bail!(
                    "{place}: the key `{shown}` is not one a client reads, so it would be ignored; the keys are {}",
                    known.join(", ")
                )
            }
        }
    }
    Ok(())
}

/// Run `minisign -Sm <file> -t <comment> [-s <key>]` over exactly the bytes of `payload` and return the
/// signature file.
fn minisign(payload: &str, secret_key: Option<&Path>) -> Result<String> {
    let dir = tempfile::tempdir().context("creating a scratch folder for the payload")?;
    let file = dir.path().join("hole.yaml");
    std::fs::write(&file, payload.as_bytes()).context("writing the payload for minisign")?;

    let mut cmd = Command::new("minisign");
    cmd.arg("-Sm").arg(&file).arg("-t").arg(TRUSTED_COMMENT);
    if let Some(key) = secret_key {
        cmd.arg("-s").arg(key);
    }
    crate::command::run_inherited(&mut cmd).map_err(|e| {
        crate::command::hint_if_not_found(e, "is minisign installed? https://jedisct1.github.io/minisign/")
    })?;

    let minisig = dir.path().join("hole.yaml.minisig");
    std::fs::read_to_string(&minisig).context("minisign did not produce a signature file")
}
