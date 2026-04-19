//! Serde `Serializer` that builds a [`DumpValue`].
//!
//! Any serializer-internal error is caught and returned as a
//! `!error` tagged string so that `Dump` remains infallible end-to-end.

use std::fmt;

use serde::ser::{
    self, Serialize, SerializeMap, SerializeSeq, SerializeStruct, SerializeStructVariant, SerializeTuple,
    SerializeTupleStruct, SerializeTupleVariant, Serializer,
};

use crate::value::tag;
use crate::DumpValue;

/// Public entry point used by the autoref ladder.
pub(crate) fn to_dump_value<T: Serialize + ?Sized>(value: &T) -> DumpValue {
    match value.serialize(DumpSerializer) {
        Ok(dv) => dv,
        Err(SerError(msg)) => DumpValue::tagged(tag::ERROR, DumpValue::String(msg)),
    }
}

#[derive(Debug)]
pub struct SerError(pub String);

impl fmt::Display for SerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for SerError {}

impl ser::Error for SerError {
    fn custom<T: fmt::Display>(msg: T) -> Self {
        SerError(msg.to_string())
    }
}

pub struct DumpSerializer;

impl Serializer for DumpSerializer {
    type Ok = DumpValue;
    type Error = SerError;
    type SerializeSeq = SeqBuilder;
    type SerializeTuple = SeqBuilder;
    type SerializeTupleStruct = SeqBuilder;
    type SerializeTupleVariant = TupleVariantBuilder;
    type SerializeMap = MapBuilder;
    type SerializeStruct = StructBuilder;
    type SerializeStructVariant = StructVariantBuilder;

    fn serialize_bool(self, v: bool) -> Result<DumpValue, SerError> {
        Ok(DumpValue::Bool(v))
    }
    fn serialize_i8(self, v: i8) -> Result<DumpValue, SerError> {
        Ok(DumpValue::Int(v.into()))
    }
    fn serialize_i16(self, v: i16) -> Result<DumpValue, SerError> {
        Ok(DumpValue::Int(v.into()))
    }
    fn serialize_i32(self, v: i32) -> Result<DumpValue, SerError> {
        Ok(DumpValue::Int(v.into()))
    }
    fn serialize_i64(self, v: i64) -> Result<DumpValue, SerError> {
        Ok(DumpValue::Int(v.into()))
    }
    fn serialize_i128(self, v: i128) -> Result<DumpValue, SerError> {
        Ok(DumpValue::Int(v))
    }
    fn serialize_u8(self, v: u8) -> Result<DumpValue, SerError> {
        Ok(DumpValue::UInt(v.into()))
    }
    fn serialize_u16(self, v: u16) -> Result<DumpValue, SerError> {
        Ok(DumpValue::UInt(v.into()))
    }
    fn serialize_u32(self, v: u32) -> Result<DumpValue, SerError> {
        Ok(DumpValue::UInt(v.into()))
    }
    fn serialize_u64(self, v: u64) -> Result<DumpValue, SerError> {
        Ok(DumpValue::UInt(v.into()))
    }
    fn serialize_u128(self, v: u128) -> Result<DumpValue, SerError> {
        Ok(DumpValue::UInt(v))
    }
    fn serialize_f32(self, v: f32) -> Result<DumpValue, SerError> {
        Ok(DumpValue::Float(v.into()))
    }
    fn serialize_f64(self, v: f64) -> Result<DumpValue, SerError> {
        Ok(DumpValue::Float(v))
    }
    fn serialize_char(self, v: char) -> Result<DumpValue, SerError> {
        let mut buf = [0u8; 4];
        Ok(DumpValue::String(v.encode_utf8(&mut buf).to_owned()))
    }
    fn serialize_str(self, v: &str) -> Result<DumpValue, SerError> {
        Ok(DumpValue::String(v.to_owned()))
    }
    fn serialize_bytes(self, v: &[u8]) -> Result<DumpValue, SerError> {
        Ok(DumpValue::Bytes(v.to_vec()))
    }
    fn serialize_none(self) -> Result<DumpValue, SerError> {
        Ok(DumpValue::Null)
    }
    fn serialize_some<T: ?Sized + Serialize>(self, value: &T) -> Result<DumpValue, SerError> {
        value.serialize(self)
    }
    fn serialize_unit(self) -> Result<DumpValue, SerError> {
        Ok(DumpValue::Null)
    }
    fn serialize_unit_struct(self, _name: &'static str) -> Result<DumpValue, SerError> {
        Ok(DumpValue::Null)
    }
    fn serialize_unit_variant(
        self,
        _name: &'static str,
        _idx: u32,
        variant: &'static str,
    ) -> Result<DumpValue, SerError> {
        Ok(DumpValue::String(variant.to_owned()))
    }
    fn serialize_newtype_struct<T: ?Sized + Serialize>(
        self,
        _name: &'static str,
        value: &T,
    ) -> Result<DumpValue, SerError> {
        value.serialize(self)
    }
    fn serialize_newtype_variant<T: ?Sized + Serialize>(
        self,
        _name: &'static str,
        _idx: u32,
        variant: &'static str,
        value: &T,
    ) -> Result<DumpValue, SerError> {
        let inner = value.serialize(DumpSerializer)?;
        Ok(DumpValue::Map(vec![(DumpValue::String(variant.to_owned()), inner)]))
    }
    fn serialize_seq(self, _len: Option<usize>) -> Result<SeqBuilder, SerError> {
        Ok(SeqBuilder { items: Vec::new() })
    }
    fn serialize_tuple(self, _len: usize) -> Result<SeqBuilder, SerError> {
        Ok(SeqBuilder { items: Vec::new() })
    }
    fn serialize_tuple_struct(self, _name: &'static str, _len: usize) -> Result<SeqBuilder, SerError> {
        Ok(SeqBuilder { items: Vec::new() })
    }
    fn serialize_tuple_variant(
        self,
        _name: &'static str,
        _idx: u32,
        variant: &'static str,
        _len: usize,
    ) -> Result<TupleVariantBuilder, SerError> {
        Ok(TupleVariantBuilder {
            variant,
            items: Vec::new(),
        })
    }
    fn serialize_map(self, _len: Option<usize>) -> Result<MapBuilder, SerError> {
        Ok(MapBuilder {
            entries: Vec::new(),
            pending_key: None,
        })
    }
    fn serialize_struct(self, _name: &'static str, _len: usize) -> Result<StructBuilder, SerError> {
        Ok(StructBuilder { entries: Vec::new() })
    }
    fn serialize_struct_variant(
        self,
        _name: &'static str,
        _idx: u32,
        variant: &'static str,
        _len: usize,
    ) -> Result<StructVariantBuilder, SerError> {
        Ok(StructVariantBuilder {
            variant,
            entries: Vec::new(),
        })
    }
}

pub struct SeqBuilder {
    items: Vec<DumpValue>,
}

impl SerializeSeq for SeqBuilder {
    type Ok = DumpValue;
    type Error = SerError;
    fn serialize_element<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), SerError> {
        self.items.push(value.serialize(DumpSerializer)?);
        Ok(())
    }
    fn end(self) -> Result<DumpValue, SerError> {
        Ok(DumpValue::Seq(self.items))
    }
}

impl SerializeTuple for SeqBuilder {
    type Ok = DumpValue;
    type Error = SerError;
    fn serialize_element<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), SerError> {
        self.items.push(value.serialize(DumpSerializer)?);
        Ok(())
    }
    fn end(self) -> Result<DumpValue, SerError> {
        Ok(DumpValue::Seq(self.items))
    }
}

impl SerializeTupleStruct for SeqBuilder {
    type Ok = DumpValue;
    type Error = SerError;
    fn serialize_field<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), SerError> {
        self.items.push(value.serialize(DumpSerializer)?);
        Ok(())
    }
    fn end(self) -> Result<DumpValue, SerError> {
        Ok(DumpValue::Seq(self.items))
    }
}

pub struct TupleVariantBuilder {
    variant: &'static str,
    items: Vec<DumpValue>,
}

impl SerializeTupleVariant for TupleVariantBuilder {
    type Ok = DumpValue;
    type Error = SerError;
    fn serialize_field<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), SerError> {
        self.items.push(value.serialize(DumpSerializer)?);
        Ok(())
    }
    fn end(self) -> Result<DumpValue, SerError> {
        Ok(DumpValue::Map(vec![(
            DumpValue::String(self.variant.to_owned()),
            DumpValue::Seq(self.items),
        )]))
    }
}

pub struct MapBuilder {
    entries: Vec<(DumpValue, DumpValue)>,
    pending_key: Option<DumpValue>,
}

impl SerializeMap for MapBuilder {
    type Ok = DumpValue;
    type Error = SerError;
    fn serialize_key<T: ?Sized + Serialize>(&mut self, key: &T) -> Result<(), SerError> {
        self.pending_key = Some(key.serialize(DumpSerializer)?);
        Ok(())
    }
    fn serialize_value<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), SerError> {
        let key = self
            .pending_key
            .take()
            .ok_or_else(|| SerError("serialize_value called before serialize_key".into()))?;
        self.entries.push((key, value.serialize(DumpSerializer)?));
        Ok(())
    }
    fn end(self) -> Result<DumpValue, SerError> {
        Ok(DumpValue::Map(self.entries))
    }
}

pub struct StructBuilder {
    entries: Vec<(DumpValue, DumpValue)>,
}

impl SerializeStruct for StructBuilder {
    type Ok = DumpValue;
    type Error = SerError;
    fn serialize_field<T: ?Sized + Serialize>(&mut self, key: &'static str, value: &T) -> Result<(), SerError> {
        self.entries
            .push((DumpValue::String(key.to_owned()), value.serialize(DumpSerializer)?));
        Ok(())
    }
    fn end(self) -> Result<DumpValue, SerError> {
        Ok(DumpValue::Map(self.entries))
    }
}

pub struct StructVariantBuilder {
    variant: &'static str,
    entries: Vec<(DumpValue, DumpValue)>,
}

impl SerializeStructVariant for StructVariantBuilder {
    type Ok = DumpValue;
    type Error = SerError;
    fn serialize_field<T: ?Sized + Serialize>(&mut self, key: &'static str, value: &T) -> Result<(), SerError> {
        self.entries
            .push((DumpValue::String(key.to_owned()), value.serialize(DumpSerializer)?));
        Ok(())
    }
    fn end(self) -> Result<DumpValue, SerError> {
        Ok(DumpValue::Map(vec![(
            DumpValue::String(self.variant.to_owned()),
            DumpValue::Map(self.entries),
        )]))
    }
}

#[cfg(test)]
#[path = "serde_bridge_tests.rs"]
mod serde_bridge_tests;
