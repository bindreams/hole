//! Built-in [`Dump`] impls for common standard-library types.
//!
//! Kept in one file for v1 so the set is easy to audit. Each section is
//! demarcated with the workspace section-comment style. A future commit
//! may split this into `impls/` topic files if it outgrows ergonomics.

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::hash::Hash;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::num::{
    NonZeroI128, NonZeroI16, NonZeroI32, NonZeroI64, NonZeroI8, NonZeroIsize, NonZeroU128, NonZeroU16, NonZeroU32,
    NonZeroU64, NonZeroU8, NonZeroUsize,
};
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

use crate::{Dump, DumpValue, YamlFormatter};

// Primitives ==========================================================================================================

macro_rules! impl_dump_signed_int {
    ($($t:ty),*) => {
        $(
            impl Dump for $t {
                fn dump(&self) -> DumpValue {
                    DumpValue::Int(*self as i128)
                }
            }
        )*
    };
}

impl_dump_signed_int!(i8, i16, i32, i64, i128, isize);

macro_rules! impl_dump_unsigned_int {
    ($($t:ty),*) => {
        $(
            impl Dump for $t {
                fn dump(&self) -> DumpValue {
                    DumpValue::UInt(*self as u128)
                }
            }
        )*
    };
}

impl_dump_unsigned_int!(u8, u16, u32, u64, u128, usize);

impl Dump for f32 {
    fn dump(&self) -> DumpValue {
        DumpValue::Float(*self as f64)
    }
}

impl Dump for f64 {
    fn dump(&self) -> DumpValue {
        DumpValue::Float(*self)
    }
}

impl Dump for bool {
    fn dump(&self) -> DumpValue {
        DumpValue::Bool(*self)
    }
}

impl Dump for char {
    fn dump(&self) -> DumpValue {
        DumpValue::String(self.to_string())
    }
}

// NonZero =============================================================================================================

macro_rules! impl_dump_nonzero_signed {
    ($($t:ident),*) => {
        $(
            impl Dump for $t {
                fn dump(&self) -> DumpValue {
                    DumpValue::Int(self.get() as i128)
                }
            }
        )*
    };
}

impl_dump_nonzero_signed!(NonZeroI8, NonZeroI16, NonZeroI32, NonZeroI64, NonZeroI128, NonZeroIsize);

macro_rules! impl_dump_nonzero_unsigned {
    ($($t:ident),*) => {
        $(
            impl Dump for $t {
                fn dump(&self) -> DumpValue {
                    DumpValue::UInt(self.get() as u128)
                }
            }
        )*
    };
}

impl_dump_nonzero_unsigned!(NonZeroU8, NonZeroU16, NonZeroU32, NonZeroU64, NonZeroU128, NonZeroUsize);

// Strings =============================================================================================================

impl Dump for String {
    fn dump(&self) -> DumpValue {
        DumpValue::String(self.clone())
    }
}

impl Dump for str {
    fn dump(&self) -> DumpValue {
        DumpValue::String(self.to_owned())
    }
}

// Box<str> is covered by the `Box<T: Dump>` blanket below.

impl Dump for Cow<'_, str> {
    fn dump(&self) -> DumpValue {
        DumpValue::String(self.to_string())
    }
}

// Paths ===============================================================================================================

impl Dump for Path {
    fn dump(&self) -> DumpValue {
        DumpValue::String(self.display().to_string())
    }
}

impl Dump for PathBuf {
    fn dump(&self) -> DumpValue {
        self.as_path().dump()
    }
}

// Option / Result =====================================================================================================

impl<T: Dump> Dump for Option<T> {
    fn dump(&self) -> DumpValue {
        match self {
            Some(v) => v.dump(),
            None => DumpValue::Null,
        }
    }
}

impl<T: Dump, E: Dump> Dump for Result<T, E> {
    fn dump(&self) -> DumpValue {
        match self {
            Ok(v) => DumpValue::Map(vec![(DumpValue::String("Ok".into()), v.dump())]),
            Err(e) => DumpValue::Map(vec![(DumpValue::String("Err".into()), e.dump())]),
        }
    }
}

// Collections =========================================================================================================

impl<T: Dump> Dump for [T] {
    fn dump(&self) -> DumpValue {
        DumpValue::Seq(self.iter().map(Dump::dump).collect())
    }
}

impl<T: Dump> Dump for Vec<T> {
    fn dump(&self) -> DumpValue {
        self.as_slice().dump()
    }
}

impl<T: Dump, const N: usize> Dump for [T; N] {
    fn dump(&self) -> DumpValue {
        self.as_slice().dump()
    }
}

impl Dump for () {
    fn dump(&self) -> DumpValue {
        DumpValue::Null
    }
}

macro_rules! impl_dump_tuple {
    ($($n:tt $t:ident),*) => {
        impl<$($t: Dump),*> Dump for ($($t,)*) {
            fn dump(&self) -> DumpValue {
                DumpValue::Seq(vec![$(self.$n.dump()),*])
            }
        }
    };
}

impl_dump_tuple!(0 T0);
impl_dump_tuple!(0 T0, 1 T1);
impl_dump_tuple!(0 T0, 1 T1, 2 T2);
impl_dump_tuple!(0 T0, 1 T1, 2 T2, 3 T3);
impl_dump_tuple!(0 T0, 1 T1, 2 T2, 3 T3, 4 T4);
impl_dump_tuple!(0 T0, 1 T1, 2 T2, 3 T3, 4 T4, 5 T5);

impl<K: Dump, V: Dump> Dump for BTreeMap<K, V> {
    fn dump(&self) -> DumpValue {
        DumpValue::Map(self.iter().map(|(k, v)| (k.dump(), v.dump())).collect())
    }
}

impl<K: Dump + Hash + Eq, V: Dump, S> Dump for HashMap<K, V, S> {
    fn dump(&self) -> DumpValue {
        let mut entries: Vec<(DumpValue, DumpValue)> = self.iter().map(|(k, v)| (k.dump(), v.dump())).collect();
        // Sort by the rendered form of the key so HashMap output is
        // byte-deterministic across runs / hasher states.
        let fmt = YamlFormatter::default();
        entries.sort_by_cached_key(|(k, _)| fmt.to_string(k));
        DumpValue::Map(entries)
    }
}

impl<T: Dump> Dump for BTreeSet<T> {
    fn dump(&self) -> DumpValue {
        DumpValue::Seq(self.iter().map(Dump::dump).collect())
    }
}

impl<T: Dump + Hash + Eq, S> Dump for HashSet<T, S> {
    fn dump(&self) -> DumpValue {
        let mut items: Vec<DumpValue> = self.iter().map(Dump::dump).collect();
        let fmt = YamlFormatter::default();
        items.sort_by_cached_key(|v| fmt.to_string(v));
        DumpValue::Seq(items)
    }
}

// Smart pointers ======================================================================================================

impl<T: Dump + ?Sized> Dump for Box<T> {
    fn dump(&self) -> DumpValue {
        (**self).dump()
    }
}

impl<T: Dump + ?Sized> Dump for Rc<T> {
    fn dump(&self) -> DumpValue {
        (**self).dump()
    }
}

impl<T: Dump + ?Sized> Dump for Arc<T> {
    fn dump(&self) -> DumpValue {
        (**self).dump()
    }
}

// Net =================================================================================================================

macro_rules! impl_dump_via_display {
    ($($t:ty),*) => {
        $(
            impl Dump for $t {
                fn dump(&self) -> DumpValue {
                    DumpValue::String(self.to_string())
                }
            }
        )*
    };
}

impl_dump_via_display!(IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6);

// Time ================================================================================================================

impl Dump for Duration {
    fn dump(&self) -> DumpValue {
        // "1.234s" style — human-readable, precise to milliseconds.
        DumpValue::String(format!("{:.3}s", self.as_secs_f64()))
    }
}

#[cfg(test)]
#[path = "impls_tests.rs"]
mod impls_tests;
