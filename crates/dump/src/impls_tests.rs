use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::num::{NonZeroI16, NonZeroU32};
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

use crate::{Dump, DumpValue};

// Primitives ==========================================================================================================

#[skuld::test]
fn int_variants_use_int_or_uint() {
    assert_eq!((-3_i32).dump(), DumpValue::Int(-3));
    assert_eq!(42_u64.dump(), DumpValue::UInt(42));
    assert_eq!(0_u128.dump(), DumpValue::UInt(0));
    assert_eq!(i128::MIN.dump(), DumpValue::Int(i128::MIN));
    assert_eq!(u128::MAX.dump(), DumpValue::UInt(u128::MAX));
}

#[skuld::test]
fn bool_and_char() {
    assert_eq!(true.dump(), DumpValue::Bool(true));
    assert_eq!('x'.dump(), DumpValue::String("x".into()));
}

#[skuld::test]
fn floats() {
    assert_eq!(1.5_f32.dump(), DumpValue::Float(1.5));
    assert_eq!(2.5_f64.dump(), DumpValue::Float(2.5));
}

#[skuld::test]
fn nonzero_ints() {
    assert_eq!(NonZeroU32::new(7).unwrap().dump(), DumpValue::UInt(7));
    assert_eq!(NonZeroI16::new(-3).unwrap().dump(), DumpValue::Int(-3));
}

// Strings + paths =====================================================================================================

#[skuld::test]
fn strings_and_refs() {
    let s = String::from("hi");
    assert_eq!(s.dump(), DumpValue::String("hi".into()));
    assert_eq!("hi".dump(), DumpValue::String("hi".into()));
    let cow: Cow<'_, str> = Cow::Borrowed("x");
    assert_eq!(cow.dump(), DumpValue::String("x".into()));
}

#[skuld::test]
fn paths() {
    let p = PathBuf::from("foo/bar");
    // PathBuf::display uses platform separators, so just check round-trip via the Path trait.
    assert_eq!(p.dump(), DumpValue::String(p.display().to_string()));
}

// Option / Result =====================================================================================================

#[skuld::test]
fn option_some_and_none() {
    assert_eq!(Some(5_i32).dump(), DumpValue::Int(5));
    assert_eq!(None::<i32>.dump(), DumpValue::Null);
}

#[skuld::test]
fn result_shape() {
    let ok: Result<i32, i32> = Ok(1);
    let err: Result<i32, i32> = Err(2);
    assert_eq!(
        ok.dump(),
        DumpValue::Map(vec![(DumpValue::String("Ok".into()), DumpValue::Int(1))])
    );
    assert_eq!(
        err.dump(),
        DumpValue::Map(vec![(DumpValue::String("Err".into()), DumpValue::Int(2))])
    );
}

// Collections =========================================================================================================

#[skuld::test]
fn vec_and_array() {
    let v = vec![1_i32, 2, 3];
    assert_eq!(
        v.dump(),
        DumpValue::Seq(vec![DumpValue::Int(1), DumpValue::Int(2), DumpValue::Int(3)])
    );
    let a: [i32; 2] = [7, 8];
    assert_eq!(a.dump(), DumpValue::Seq(vec![DumpValue::Int(7), DumpValue::Int(8)]));
}

#[skuld::test]
fn tuple() {
    assert_eq!(
        (1_i32, "two").dump(),
        DumpValue::Seq(vec![DumpValue::Int(1), DumpValue::String("two".into()),])
    );
}

#[skuld::test]
fn btreemap_preserves_key_order() {
    let mut m = BTreeMap::new();
    m.insert("b", 2_i32);
    m.insert("a", 1);
    assert_eq!(
        m.dump(),
        DumpValue::Map(vec![
            (DumpValue::String("a".into()), DumpValue::Int(1)),
            (DumpValue::String("b".into()), DumpValue::Int(2)),
        ])
    );
}

#[skuld::test]
fn hashmap_output_is_deterministic() {
    // Sort order is by YAML-rendered key. Build the same map twice and
    // confirm identical output regardless of hasher state.
    let mut m1 = HashMap::new();
    m1.insert("zoo", 1_i32);
    m1.insert("apple", 2);
    m1.insert("mid", 3);

    let mut m2 = HashMap::new();
    m2.insert("mid", 3_i32);
    m2.insert("apple", 2);
    m2.insert("zoo", 1);

    assert_eq!(m1.dump(), m2.dump());
    // Also confirm the actual sort order is alphabetical.
    let DumpValue::Map(entries) = m1.dump() else {
        panic!("expected map")
    };
    let keys: Vec<_> = entries
        .into_iter()
        .map(|(k, _)| match k {
            DumpValue::String(s) => s,
            _ => unreachable!(),
        })
        .collect();
    assert_eq!(keys, vec!["apple", "mid", "zoo"]);
}

#[skuld::test]
fn sets() {
    let bt: BTreeSet<i32> = [3, 1, 2].into_iter().collect();
    assert_eq!(
        bt.dump(),
        DumpValue::Seq(vec![DumpValue::Int(1), DumpValue::Int(2), DumpValue::Int(3)])
    );
    let hs: HashSet<&'static str> = ["zoo", "apple", "mid"].into_iter().collect();
    let DumpValue::Seq(items) = hs.dump() else {
        panic!("expected seq")
    };
    let rendered: Vec<_> = items
        .into_iter()
        .map(|v| match v {
            DumpValue::String(s) => s,
            _ => unreachable!(),
        })
        .collect();
    assert_eq!(rendered, vec!["apple", "mid", "zoo"]);
}

// Smart pointers ======================================================================================================

#[skuld::test]
fn smart_pointers_delegate() {
    let b: Box<i32> = Box::new(5);
    let r: Rc<i32> = Rc::new(7);
    let a: Arc<i32> = Arc::new(9);
    assert_eq!(b.dump(), DumpValue::Int(5));
    assert_eq!(r.dump(), DumpValue::Int(7));
    assert_eq!(a.dump(), DumpValue::Int(9));
}

// Net =================================================================================================================

#[skuld::test]
fn net_types_render_as_strings() {
    let ip: IpAddr = Ipv4Addr::new(10, 0, 0, 1).into();
    assert_eq!(ip.dump(), DumpValue::String("10.0.0.1".into()));
    let sa: SocketAddr = "127.0.0.1:8080".parse().unwrap();
    assert_eq!(sa.dump(), DumpValue::String("127.0.0.1:8080".into()));
}

// Time ================================================================================================================

#[skuld::test]
fn duration_renders_with_millisecond_precision() {
    assert_eq!(Duration::from_millis(1_234).dump(), DumpValue::String("1.234s".into()));
    assert_eq!(Duration::from_secs(0).dump(), DumpValue::String("0.000s".into()));
}
