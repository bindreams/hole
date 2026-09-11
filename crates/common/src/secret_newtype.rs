//! `secret_newtype!` — the shared shape behind
//! [`crate::config::ServerAddress`] and [`crate::config::Password`]: a
//! `String` newtype with no `Display` and no `Deref`, a single named exit
//! (`expose()`), a hand-written redacting `Debug`, and a `Dump` impl tagged
//! `dump::tag::SECRET`.
//!
//! The two types differ only in name and in the noun their `expose()` doc
//! uses ("address" / "secret"); everything else — derives, the `From` impls,
//! the exact `Debug` output, the `Dump` tag — is identical, and pinned for
//! both by the same `tests/secret_shape/*.rs` trybuild fixtures and the same
//! `the_secret_newtypes_have_no_second_exit` test (`crates/common/src/config_tests.rs`).
//! This macro exists so that identity holds by construction rather than by
//! two hand-kept copies staying in sync.
//!
//! The struct's own rationale (why *this* type needs the no-`Display`/no-`Deref`
//! shape) belongs on the struct itself — pass it as the doc comment inside the
//! invocation, exactly as you would on a bare `struct` declaration.

/// Generates a secret-shaped `String` newtype. See the module doc for what
/// that shape is and why.
///
/// ```ignore
/// secret_newtype! {
///     /// A configured server address.
///     pub struct ServerAddress;
///     noun = "address";
/// }
/// ```
#[macro_export]
macro_rules! secret_newtype {
    (
        $(#[$meta:meta])*
        $vis:vis struct $name:ident;
        noun = $noun:literal;
    ) => {
        $(#[$meta])*
        #[derive(Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
        #[serde(transparent)]
        $vis struct $name(String);

        impl $name {
            pub fn new(secret: impl Into<String>) -> Self {
                Self(secret.into())
            }

            #[doc = concat!(
                "The ", $noun, " in clear. Every caller is a site that genuinely ",
                "needs to dial, compare, or persist it — never a log field."
            )]
            pub fn expose(&self) -> &str {
                &self.0
            }
        }

        impl From<&str> for $name {
            fn from(value: &str) -> Self {
                Self::new(value)
            }
        }

        impl From<String> for $name {
            fn from(value: String) -> Self {
                Self::new(value)
            }
        }

        impl std::fmt::Debug for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(concat!(stringify!($name), "(<redacted>)"))
            }
        }

        impl dump::Dump for $name {
            fn dump(&self) -> dump::DumpValue {
                dump::DumpValue::tagged(dump::tag::SECRET, dump::DumpValue::String(self.0.clone()))
            }
        }
    };
}
