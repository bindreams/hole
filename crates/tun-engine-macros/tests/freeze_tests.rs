//! Runtime behavior tests for `#[freeze]`.
//!
//! Compile-fail cases live under `tests/compile_fail/` and are driven via
//! `trybuild` from the `compile_fail` test below.

use std::sync::Arc;
use std::time::Duration;

use tun_engine_macros::freeze;

fn main() {
    skuld::run_all();
}

// Basic ===============================================================================================================

#[freeze]
pub struct Basic {
    pub a: usize,
    pub b: u16,
}

#[skuld::test]
fn basic_field_read() {
    let mut m = MutBasic { a: 0, b: 0 };
    m.a = 42;
    m.b = 1337;
    let b = m.freeze();
    assert_eq!(b.a, 42);
    assert_eq!(b.b, 1337);
}

#[skuld::test]
fn basic_field_read_by_reference() {
    // Ensure Deref works transitively — e.g. inside functions that take
    // &Basic and read fields.
    fn read_a(b: &Basic) -> usize {
        b.a
    }
    let frozen = MutBasic { a: 7, b: 1 }.freeze();
    assert_eq!(read_a(&frozen), 7);
}

// Various types =======================================================================================================

#[freeze]
pub struct Kitchen {
    pub u: usize,
    pub s: String,
    pub opt: Option<u32>,
    pub arc: Arc<str>,
    pub vec: Vec<u8>,
    pub dur: Duration,
}

#[skuld::test]
fn kitchen_sink_types() {
    let m = MutKitchen {
        u: 1,
        s: "hi".into(),
        opt: Some(2),
        arc: Arc::from("x"),
        vec: vec![1, 2, 3],
        dur: Duration::from_millis(500),
    };
    let f = m.freeze();
    assert_eq!(f.u, 1);
    assert_eq!(f.s, "hi");
    assert_eq!(f.opt, Some(2));
    assert_eq!(&*f.arc, "x");
    assert_eq!(f.vec, vec![1, 2, 3]);
    assert_eq!(f.dur, Duration::from_millis(500));
}

// Trait objects =======================================================================================================

pub trait MyTrait: Send + Sync {
    fn value(&self) -> u32;
}

struct Concrete(u32);
impl MyTrait for Concrete {
    fn value(&self) -> u32 {
        self.0
    }
}

#[freeze]
pub struct WithDyn {
    pub boxed: Box<dyn MyTrait>,
    pub maybe: Option<Arc<dyn MyTrait>>,
}

#[skuld::test]
fn dyn_fields_work() {
    let m = MutWithDyn {
        boxed: Box::new(Concrete(7)),
        maybe: Some(Arc::new(Concrete(9))),
    };
    let f = m.freeze();
    assert_eq!(f.boxed.value(), 7);
    assert_eq!(f.maybe.as_ref().unwrap().value(), 9);
}

// Default derive ======================================================================================================

#[freeze]
#[derive(Default)]
pub struct WithDefault {
    pub count: usize,
    pub name: String,
    pub opt: Option<u16>,
}

#[skuld::test]
fn default_derive_on_mut() {
    let m: MutWithDefault = Default::default();
    assert_eq!(m.count, 0);
    assert_eq!(m.name, "");
    assert_eq!(m.opt, None);
}

#[skuld::test]
fn default_derive_on_frozen() {
    let f: WithDefault = Default::default();
    assert_eq!(f.count, 0);
    assert_eq!(f.name, "");
    assert_eq!(f.opt, None);
}

#[skuld::test]
fn default_derive_closure_style() {
    // The idiomatic `Engine::build(... , |c| {...})` usage — demonstrate
    // that a caller with only Default and field access can assemble a
    // frozen config without naming every field.
    fn build_like<F: FnOnce(&mut MutWithDefault)>(f: F) -> WithDefault {
        let mut c = MutWithDefault::default();
        f(&mut c);
        c.freeze()
    }
    let f = build_like(|c| {
        c.count = 99;
        c.name = "hello".into();
    });
    assert_eq!(f.count, 99);
    assert_eq!(f.name, "hello");
    assert_eq!(f.opt, None);
}

// Visibility ==========================================================================================================

mod vis_check {
    use tun_engine_macros::freeze;

    #[freeze]
    pub(crate) struct CrateVis {
        pub x: u32,
    }

    pub(crate) fn make(x: u32) -> CrateVis {
        MutCrateVis { x }.freeze()
    }
}

#[skuld::test]
fn pub_crate_visibility_propagates() {
    let f = vis_check::make(5);
    assert_eq!(f.x, 5);
}

// Doc comments ========================================================================================================

#[freeze]
/// An example struct with documentation.
pub struct Documented {
    /// Number of widgets.
    pub widgets: usize,
}

#[skuld::test]
fn documented_struct_constructs() {
    let f = MutDocumented { widgets: 3 }.freeze();
    assert_eq!(f.widgets, 3);
}

// Compile-fail tests driven by trybuild ===============================================================================

#[skuld::test]
fn compile_fail() {
    // Runs only when explicitly invoked; skipped if the trybuild env var isn't set.
    // On CI this runs as part of the test suite — a fresh build verifies each
    // listed .rs file fails to compile with the expected error.
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/compile_fail/*.rs");
    t.pass("tests/compile_pass/*.rs");
}
