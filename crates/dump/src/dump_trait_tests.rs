use super::Dump;
use crate::DumpValue;

struct Marker;

impl Dump for Marker {
    fn dump(&self) -> DumpValue {
        DumpValue::String("marker".into())
    }
}

#[skuld::test]
fn ref_and_mut_ref_delegate_to_inner() {
    let m = Marker;
    let r = &m;
    let expected = DumpValue::String("marker".into());
    assert_eq!(m.dump(), expected);
    assert_eq!(r.dump(), expected);

    let mut m2 = Marker;
    let rm: &mut Marker = &mut m2;
    assert_eq!(rm.dump(), expected);
}

#[skuld::test]
fn double_ref_also_delegates() {
    let m = Marker;
    let r = &m;
    let rr = &r;
    assert_eq!(rr.dump(), DumpValue::String("marker".into()));
}
