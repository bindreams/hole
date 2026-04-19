//! Debug-fallback rung of the autoref ladder.

use std::fmt::Debug;

use crate::value::tag;
use crate::DumpValue;

/// Emit any `Debug` value as `!debug "<formatted>"`.
pub(crate) fn to_dump_value<T: Debug + ?Sized>(value: &T) -> DumpValue {
    DumpValue::tagged(tag::DEBUG, DumpValue::String(format!("{:?}", value)))
}
