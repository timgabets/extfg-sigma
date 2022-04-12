use std::borrow::Cow;
use std::collections::BTreeMap;

use bytes::{Bytes, BytesMut};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::util::*;

#[macro_use]
mod util;

#[cfg(feature = "codec")]
pub mod codec;

#[derive(Debug, thiserror::Error, PartialEq, Clone)]
pub enum Error {
    #[error("{0}")]
    Bounds(String),
    #[error("Incorrect tag: {0}")]
    IncorrectTag(String),
    #[error("Incorrect field '{field_name}', should be {should_be}")]
    IncorrectFieldData {
        field_name: String,
        should_be: String,
    },
    #[error("Missing field '{0}'")]
    MissingField(String),
    #[error("{0}")]
    IncorrectData(String),
}

impl Error {
    fn incorrect_field_data(field_name: &str, should_be: &str) -> Self {
        Self::IncorrectFieldData {
            field_name: field_name.into(),
            should_be: should_be.into(),
        }
    }
}

fn validate_mti(s: &str) -> Result<(), Error> {
    let b = s.as_bytes();
    if b.len() != 4 {
        return Err(Error::incorrect_field_data(
            "MTI",
            "4 digit number (string)",
        ));
    }
    for x in b.iter() {
        if !matches!(x, b'0'..=b'9') {
            return Err(Error::incorrect_field_data(
                "MTI",
                "4 digit number (string)",
            ));
        }
    }
    Ok(())
}

fn validate_source(s: &str) -> Result<(), Error> {
    if s.len() != 1 {
        return Err(Error::incorrect_field_data("SRC", "single ASCII char"));
    }
    Ok(())
}

fn validate_saf(s: &str) -> Result<(), Error> {
    match s {
        "Y" | "N" => Ok(()),
        _ => Err(Error::incorrect_field_data("SAF", "char Y or N")),
    }
}

#[derive(Debug, PartialEq, Clone)]
pub enum IsoFieldData {
    String(String),
    Raw(Vec<u8>),
}

impl IsoFieldData {
    pub fn to_string_lossy(self) -> String {
        match self {
            Self::String(v) => v,
            Self::Raw(v) => String::from_utf8(v)
                .unwrap_or_else(|err| String::from_utf8_lossy(err.as_bytes()).into_owned()),
        }
    }

    pub fn to_cow_str_lossy<'a, 'b: 'a>(&'b self) -> Cow<'a, str> {
        match self {
            Self::String(ref v) => Cow::Borrowed(v),
            Self::Raw(ref v) => String::from_utf8_lossy(v),
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        match self {
            IsoFieldData::String(x) => x.as_bytes(),
            IsoFieldData::Raw(x) => x,
        }
    }

    pub fn from_bytes(data: Bytes) -> Self {
        let vec = data.to_vec();
        String::from_utf8(vec).map_or_else(|err| Self::Raw(err.into_bytes()), Self::String)
    }
}

impl From<String> for IsoFieldData {
    fn from(v: String) -> Self {
        Self::String(v)
    }
}

impl From<&str> for IsoFieldData {
    fn from(v: &str) -> Self {
        Self::String(v.into())
    }
}

impl From<Vec<u8>> for IsoFieldData {
    fn from(v: Vec<u8>) -> Self {
        Self::Raw(v)
    }
}

impl From<&[u8]> for IsoFieldData {
    fn from(v: &[u8]) -> Self {
        Self::Raw(Vec::from(v))
    }
}

impl<T: AsRef<[u8]> + ?Sized> PartialEq<T> for IsoFieldData {
    fn eq(&self, other: &T) -> bool {
        self.as_bytes() == other.as_ref()
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct SigmaRequest {
    saf: String,
    source: String,
    mti: String,
    pub auth_serno: u64,
    pub tags: BTreeMap<u16, String>,
    pub iso_fields: BTreeMap<u16, IsoFieldData>,
    pub iso_subfields: BTreeMap<(u16, u8), IsoFieldData>,
}

impl SigmaRequest {
    pub fn new(saf: &str, source: &str, mti: &str, auth_serno: u64) -> Result<Self, Error> {
        validate_saf(saf)?;
        validate_source(source)?;
        validate_mti(mti)?;
        Ok(Self {
            saf: saf.into(),
            source: source.into(),
            mti: mti.into(),
            auth_serno,
            tags: Default::default(),
            iso_fields: Default::default(),
            iso_subfields: Default::default(),
        })
    }

    pub fn from_json_value(mut data: Value) -> Result<SigmaRequest, Error> {
        let data = data
            .as_object_mut()
            .ok_or_else(|| Error::IncorrectData("SigmaRequest JSON should be object".into()))?;
        let mut req = Self::new("N", "X", "0100", 0)?;

        macro_rules! fill_req_field {
            ($fname:ident, $pname:literal, $comment:literal) => {
                match data.remove($pname) {
                    Some(x) => match x.as_str() {
                        Some(v) => {
                            req.$fname(v.to_string())?;
                        }
                        None => {
                            return Err(Error::IncorrectFieldData {
                                field_name: $pname.to_string(),
                                should_be: $comment.to_string(),
                            });
                        }
                    },
                    None => {
                        return Err(Error::MissingField($pname.to_string()));
                    }
                }
            };
        }

        fill_req_field!(set_saf, "SAF", "String");
        fill_req_field!(set_source, "SRC", "String");
        fill_req_field!(set_mti, "MTI", "String");
        // Authorization serno
        match data.remove("Serno") {
            Some(x) => {
                if let Some(s) = x.as_str() {
                    req.auth_serno = s.parse::<u64>().map_err(|_| Error::IncorrectFieldData {
                        field_name: "Serno".into(),
                        should_be: "integer".into(),
                    })?;
                } else if let Some(v) = x.as_u64() {
                    req.auth_serno = v;
                } else {
                    return Err(Error::IncorrectFieldData {
                        field_name: "Serno".into(),
                        should_be: "u64 or String with integer".into(),
                    });
                }
            }
            None => {
                req.auth_serno = util::gen_random_auth_serno();
            }
        }

        for (name, field_data) in data.iter() {
            let tag = Tag::from_str(name)?;
            let content = if let Some(x) = field_data.as_str() {
                x.into()
            } else if let Some(x) = field_data.as_u64() {
                format!("{}", x)
            } else {
                return Err(Error::IncorrectFieldData {
                    field_name: name.clone(),
                    should_be: "u64 or String with integer".into(),
                });
            };
            match tag {
                Tag::Regular(i) => {
                    req.tags.insert(i, content);
                }
                Tag::Iso(i) => {
                    req.iso_fields.insert(i, content.into());
                }
                Tag::IsoSubfield(i, si) => {
                    req.iso_subfields.insert((i, si), content.into());
                }
            }
        }

        Ok(req)
    }

    pub fn encode(&self) -> Result<Bytes, Error> {
        let mut buf = BytesMut::with_capacity(8192);
        buf.extend_from_slice(b"00000");

        buf.extend_from_slice(self.saf.as_bytes());
        buf.extend_from_slice(self.source.as_bytes());
        buf.extend_from_slice(self.mti.as_bytes());
        if self.auth_serno > 9999999999 {
            buf.extend_from_slice(&format!("{}", self.auth_serno).as_bytes()[0..10]);
        } else {
            buf.extend_from_slice(format!("{:010}", self.auth_serno).as_bytes());
        }

        for (k, v) in self.tags.iter() {
            encode_field_to_buf(Tag::Regular(*k), v.as_bytes(), &mut buf)?;
        }

        for (k, v) in self.iso_fields.iter() {
            encode_field_to_buf(Tag::Iso(*k), v.as_bytes(), &mut buf)?;
        }

        for ((k, k1), v) in self.iso_subfields.iter() {
            encode_field_to_buf(Tag::IsoSubfield(*k, *k1), v.as_bytes(), &mut buf)?;
        }

        let msg_len = buf.len() - 5;
        buf[0..5].copy_from_slice(format!("{:05}", msg_len).as_bytes());
        Ok(buf.freeze())
    }

    pub fn decode(mut data: Bytes) -> Result<Self, Error> {
        let mut req = Self::new("N", "X", "0100", 0)?;

        let msg_len = parse_ascii_bytes_lossy!(
            &bytes_split_to(&mut data, 5)?,
            usize,
            Error::incorrect_field_data("message length", "valid integer")
        )?;
        let mut data = bytes_split_to(&mut data, msg_len)?;

        req.set_saf(String::from_utf8_lossy(&bytes_split_to(&mut data, 1)?).to_string())?;
        req.set_source(String::from_utf8_lossy(&bytes_split_to(&mut data, 1)?).to_string())?;
        req.set_mti(String::from_utf8_lossy(&bytes_split_to(&mut data, 4)?).to_string())?;
        req.auth_serno = String::from_utf8_lossy(&bytes_split_to(&mut data, 10)?)
            .trim()
            .parse::<u64>()
            .map_err(|_| Error::IncorrectFieldData {
                field_name: "Serno".into(),
                should_be: "u64".into(),
            })?;

        while !data.is_empty() {
            let (tag, data_src) = decode_field_from_cursor(&mut data)?;

            match tag {
                Tag::Regular(i) => {
                    req.tags
                        .insert(i, String::from_utf8_lossy(&data_src).into_owned());
                }
                Tag::Iso(i) => {
                    req.iso_fields.insert(i, IsoFieldData::from_bytes(data_src));
                }
                Tag::IsoSubfield(i, si) => {
                    req.iso_subfields
                        .insert((i, si), IsoFieldData::from_bytes(data_src));
                }
            }
        }

        Ok(req)
    }

    pub fn saf(&self) -> &str {
        &self.saf
    }

    pub fn set_saf(&mut self, v: String) -> Result<(), Error> {
        validate_saf(&v)?;
        self.saf = v;
        Ok(())
    }

    pub fn source(&self) -> &str {
        &self.source
    }

    pub fn set_source(&mut self, v: String) -> Result<(), Error> {
        validate_source(&v)?;
        self.source = v;
        Ok(())
    }

    pub fn mti(&self) -> &str {
        &self.mti
    }

    pub fn set_mti(&mut self, v: String) -> Result<(), Error> {
        validate_mti(&v)?;
        self.mti = v;
        Ok(())
    }
}

#[derive(Deserialize, Serialize, Debug, Clone, PartialEq, Eq)]
pub struct FeeData {
    pub reason: u16,
    pub currency: u16,
    pub amount: u64,
}

impl FeeData {
    pub fn from_slice(data: &[u8]) -> Result<Self, Error> {
        if data.len() >= 8 {
            // "\x00\x32\x00\x00\x108116978300"
            let reason = parse_ascii_bytes_lossy!(
                &data[0..4],
                u16,
                Error::incorrect_field_data("FeeData.reason", "valid integer")
            )?;
            let currency = parse_ascii_bytes_lossy!(
                &data[4..7],
                u16,
                Error::incorrect_field_data("FeeData.currency", "valid integer")
            )?;
            let amount = parse_ascii_bytes_lossy!(
                &data[7..],
                u64,
                Error::incorrect_field_data("FeeData.amount", "valid integer")
            )?;
            Ok(Self {
                reason,
                currency,
                amount,
            })
        } else {
            Err(Error::IncorrectData(
                "FeeData slice should be longer than 8 bytes".into(),
            ))
        }
    }

    pub fn encode(&self) -> Result<Bytes, Error> {
        let mut buf = BytesMut::new();

        if self.reason > 9999 {
            return Err(Error::Bounds(
                "FeeData.reason should be less or equal 9999".into(),
            ));
        }
        buf.extend_from_slice(format!("{:<04}", self.reason).as_bytes());

        if self.currency > 999 {
            return Err(Error::Bounds(
                "FeeData.reason should be less or equal 999".into(),
            ));
        }
        buf.extend_from_slice(format!("{:<03}", self.currency).as_bytes());

        buf.extend_from_slice(format!("{}", self.amount).as_bytes());

        Ok(buf.freeze())
    }
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct SigmaResponse {
    mti: String,
    pub auth_serno: u64,
    pub reason: u32,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub fees: Vec<FeeData>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub adata: Option<String>,
}

impl SigmaResponse {
    pub fn new(mti: &str, auth_serno: u64, reason: u32) -> Result<Self, Error> {
        validate_mti(mti)?;
        Ok(Self {
            mti: mti.into(),
            auth_serno,
            reason,
            fees: Vec::new(),
            adata: Option::None,
        })
    }

    pub fn decode(mut data: Bytes) -> Result<Self, Error> {
        let mut resp = Self::new("0100", 0, 0)?;

        let msg_len = parse_ascii_bytes_lossy!(
            &bytes_split_to(&mut data, 5)?,
            usize,
            Error::incorrect_field_data("message length", "valid integer")
        )?;
        let mut data = bytes_split_to(&mut data, msg_len)?;

        resp.set_mti(String::from_utf8_lossy(&bytes_split_to(&mut data, 4)?).to_string())?;
        resp.auth_serno = String::from_utf8_lossy(&bytes_split_to(&mut data, 10)?)
            .trim()
            .parse::<u64>()
            .map_err(|_| Error::IncorrectFieldData {
                field_name: "Serno".into(),
                should_be: "u64".into(),
            })?;

        while !data.is_empty() {
            /*
             *  |
             *  |  T  | \x00 | \x31 | \x00 | \x00 | \x04 |  8  |  1  |  0  |  0  |
             *        |             |      |             |                       |
             *        |__ tag id ___|      |tag data len |_______ data __________|
             */
            let (tag, data_src) = decode_field_from_cursor(&mut data)?;

            match tag {
                Tag::Regular(31) => {
                    resp.reason = parse_ascii_bytes_lossy!(
                        &data_src,
                        u32,
                        Error::incorrect_field_data("reason", "shloud be u32")
                    )?;
                }
                Tag::Regular(32) => {
                    resp.fees.push(FeeData::from_slice(&data_src)?);
                }
                Tag::Regular(48) => {
                    resp.adata = Some(String::from_utf8_lossy(&data_src).to_string());
                }
                _ => {}
            }
        }

        Ok(resp)
    }

    pub fn mti(&self) -> &str {
        &self.mti
    }

    pub fn set_mti(&mut self, v: String) -> Result<(), Error> {
        validate_mti(&v)?;
        self.mti = v;
        Ok(())
    }

    pub fn encode(&self) -> Result<Bytes, Error> {
        let mut buf = BytesMut::with_capacity(8192);
        buf.extend_from_slice(b"00000");

        buf.extend_from_slice(self.mti.as_bytes());
        if self.auth_serno > 9999999999 {
            buf.extend_from_slice(&format!("{}", self.auth_serno).as_bytes()[0..10]);
        } else {
            buf.extend_from_slice(format!("{:010}", self.auth_serno).as_bytes());
        }
        encode_field_to_buf(
            Tag::Regular(31),
            format!("{}", self.reason).as_bytes(),
            &mut buf,
        )?;
        for i in &self.fees {
            encode_field_to_buf(Tag::Regular(32), &i.encode()?, &mut buf)?;
        }
        if let Some(ref adata) = self.adata {
            encode_field_to_buf(Tag::Regular(48), adata.as_bytes(), &mut buf)?;
        }

        let msg_len = buf.len() - 5;
        buf[0..5].copy_from_slice(format!("{:05}", msg_len).as_bytes());
        Ok(buf.freeze())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ok() {
        let payload = r#"{
            "SAF": "Y",
            "SRC": "M",
            "MTI": "0200",
            "Serno": 6007040979,
            "T0000": 2371492071643,
            "T0001": "C",
            "T0002": 643,
            "T0003": "000100000000",
            "T0004": 978,
            "T0005": "000300000000",
            "T0006": "OPS6",
            "T0007": 19,
            "T0008": 643,
            "T0009": 3102,
            "T0010": 3104,
            "T0011": 2,
            "T0014": "IDDQD Bank",
            "T0016": 74707182,
            "T0018": "Y",
            "T0022": "000000000010",
            "i000": "0100",
            "i002": "555544******1111",
            "i003": "500000",
            "i004": "000100000000",
            "i006": "000100000000",
            "i007": "0629151748",
            "i011": "100250",
            "i012": "181748",
            "i013": "0629",
            "i018": "0000",
            "i022": "0000",
            "i025": "02",
            "i032": "010455",
            "i037": "002595100250",
            "i041": 990,
            "i042": "DCZ1",
            "i043": "IDDQD Bank.                         GE",
            "i048": "USRDT|2595100250",
            "i049": 643,
            "i051": 643,
            "i060": 3,
            "i101": 91926242,
            "i102": 2371492071643
        }"#;

        let r: SigmaRequest =
            SigmaRequest::from_json_value(serde_json::from_str(payload).unwrap()).unwrap();
        assert_eq!(r.saf, "Y");
        assert_eq!(r.source, "M");
        assert_eq!(r.mti, "0200");
        assert_eq!(r.auth_serno, 6007040979);
        assert_eq!(r.tags.get(&0).unwrap(), "2371492071643");
        assert_eq!(r.tags.get(&1).unwrap(), "C");
        assert_eq!(r.tags.get(&2).unwrap(), "643");
        assert_eq!(r.tags.get(&3).unwrap(), "000100000000");
        assert_eq!(r.tags.get(&4).unwrap(), "978");
        assert_eq!(r.tags.get(&5).unwrap(), "000300000000");
        assert_eq!(r.tags.get(&6).unwrap(), "OPS6");
        assert_eq!(r.tags.get(&7).unwrap(), "19");
        assert_eq!(r.tags.get(&8).unwrap(), "643");
        assert_eq!(r.tags.get(&9).unwrap(), "3102");
        assert_eq!(r.tags.get(&10).unwrap(), "3104");
        assert_eq!(r.tags.get(&11).unwrap(), "2");

        if r.tags.get(&12).is_some() {
            unreachable!();
        }

        if r.tags.get(&13).is_some() {
            unreachable!();
        }

        assert_eq!(r.tags.get(&14).unwrap(), "IDDQD Bank");

        if r.tags.get(&15).is_some() {
            unreachable!();
        }

        assert_eq!(r.tags.get(&16).unwrap(), "74707182");
        if r.tags.get(&17).is_some() {
            unreachable!();
        }
        assert_eq!(r.tags.get(&18).unwrap(), "Y");
        assert_eq!(r.tags.get(&22).unwrap(), "000000000010");

        assert_eq!(r.iso_fields.get(&0).unwrap(), "0100");

        if r.iso_fields.get(&1).is_some() {
            unreachable!();
        }

        assert_eq!(r.iso_fields.get(&2).unwrap(), "555544******1111");
        assert_eq!(r.iso_fields.get(&3).unwrap(), "500000");
        assert_eq!(r.iso_fields.get(&4).unwrap(), "000100000000");
        assert_eq!(r.iso_fields.get(&6).unwrap(), "000100000000");
        assert_eq!(r.iso_fields.get(&7).unwrap(), "0629151748");
        assert_eq!(r.iso_fields.get(&11).unwrap(), "100250");
        assert_eq!(r.iso_fields.get(&12).unwrap(), "181748");
        assert_eq!(r.iso_fields.get(&13).unwrap(), "0629");
        assert_eq!(r.iso_fields.get(&18).unwrap(), "0000");
        assert_eq!(r.iso_fields.get(&22).unwrap(), "0000");
        assert_eq!(r.iso_fields.get(&25).unwrap(), "02");
        assert_eq!(r.iso_fields.get(&32).unwrap(), "010455");
        assert_eq!(r.iso_fields.get(&37).unwrap(), "002595100250");
        assert_eq!(r.iso_fields.get(&41).unwrap(), "990");
        assert_eq!(r.iso_fields.get(&42).unwrap(), "DCZ1");
        assert_eq!(
            r.iso_fields.get(&43).unwrap(),
            "IDDQD Bank.                         GE"
        );
        assert_eq!(r.iso_fields.get(&48).unwrap(), "USRDT|2595100250");
        assert_eq!(r.iso_fields.get(&49).unwrap(), "643");
        assert_eq!(r.iso_fields.get(&51).unwrap(), "643");
        assert_eq!(r.iso_fields.get(&60).unwrap(), "3");
        assert_eq!(r.iso_fields.get(&101).unwrap(), "91926242");
        assert_eq!(r.iso_fields.get(&102).unwrap(), "2371492071643");
    }

    #[test]
    fn serno_as_string() {
        let payload = r#"{
            "SAF": "Y",
            "SRC": "M",
            "MTI": "0200",
            "Serno": "0600704097",
            "T0000": 2371492071643,
            "T0001": "C",
            "T0002": 643,
            "T0003": "000100000000",
            "T0004": 978,
            "T0005": "000300000000",
            "T0006": "OPS6",
            "T0007": 19,
            "T0008": 643,
            "T0009": 3102,
            "T0010": 3104,
            "T0011": 2,
            "T0014": "IDDQD Bank",
            "T0016": 74707182,
            "T0018": "Y",
            "T0022": "000000000010",
            "i000": "0100",
            "i002": "555544******1111",
            "i003": "500000",
            "i004": "000100000000",
            "i006": "000100000000",
            "i007": "0629151748",
            "i011": "100250",
            "i012": "181748",
            "i013": "0629",
            "i018": "0000",
            "i022": "0000",
            "i025": "02",
            "i032": "010455",
            "i037": "002595100250",
            "i041": 990,
            "i042": "DCZ1",
            "i043": "IDDQD Bank.                         GE",
            "i048": "USRDT|2595100250",
            "i049": 643,
            "i051": 643,
            "i060": 3,
            "i101": 91926242,
            "i102": 2371492071643
        }"#;

        let r: SigmaRequest =
            SigmaRequest::from_json_value(serde_json::from_str(payload).unwrap()).unwrap();
        assert_eq!(r.saf, "Y");
        assert_eq!(r.source, "M");
        assert_eq!(r.mti, "0200");
        assert_eq!(r.auth_serno, 600704097);
        assert_eq!(r.tags.get(&0).unwrap(), "2371492071643");
        assert_eq!(r.tags.get(&1).unwrap(), "C");
        assert_eq!(r.tags.get(&2).unwrap(), "643");
        assert_eq!(r.tags.get(&3).unwrap(), "000100000000");
        assert_eq!(r.tags.get(&4).unwrap(), "978");
        assert_eq!(r.tags.get(&5).unwrap(), "000300000000");
        assert_eq!(r.tags.get(&6).unwrap(), "OPS6");
        assert_eq!(r.tags.get(&7).unwrap(), "19");
        assert_eq!(r.tags.get(&8).unwrap(), "643");
        assert_eq!(r.tags.get(&9).unwrap(), "3102");
        assert_eq!(r.tags.get(&10).unwrap(), "3104");
        assert_eq!(r.tags.get(&11).unwrap(), "2");

        if r.tags.get(&12).is_some() {
            unreachable!();
        }

        if r.tags.get(&13).is_some() {
            unreachable!();
        }

        assert_eq!(r.tags.get(&14).unwrap(), "IDDQD Bank");

        if r.tags.get(&15).is_some() {
            unreachable!();
        }

        assert_eq!(r.tags.get(&16).unwrap(), "74707182");
        if r.tags.get(&17).is_some() {
            unreachable!();
        }
        assert_eq!(r.tags.get(&18).unwrap(), "Y");
        assert_eq!(r.tags.get(&22).unwrap(), "000000000010");

        assert_eq!(r.iso_fields.get(&0).unwrap(), "0100");

        if r.iso_fields.get(&1).is_some() {
            unreachable!();
        }

        assert_eq!(r.iso_fields.get(&2).unwrap(), "555544******1111");
        assert_eq!(r.iso_fields.get(&3).unwrap(), "500000");
        assert_eq!(r.iso_fields.get(&4).unwrap(), "000100000000");
        assert_eq!(r.iso_fields.get(&6).unwrap(), "000100000000");
        assert_eq!(r.iso_fields.get(&7).unwrap(), "0629151748");
        assert_eq!(r.iso_fields.get(&11).unwrap(), "100250");
        assert_eq!(r.iso_fields.get(&12).unwrap(), "181748");
        assert_eq!(r.iso_fields.get(&13).unwrap(), "0629");
        assert_eq!(r.iso_fields.get(&18).unwrap(), "0000");
        assert_eq!(r.iso_fields.get(&22).unwrap(), "0000");
        assert_eq!(r.iso_fields.get(&25).unwrap(), "02");
        assert_eq!(r.iso_fields.get(&32).unwrap(), "010455");
        assert_eq!(r.iso_fields.get(&37).unwrap(), "002595100250");
        assert_eq!(r.iso_fields.get(&41).unwrap(), "990");
        assert_eq!(r.iso_fields.get(&42).unwrap(), "DCZ1");
        assert_eq!(
            r.iso_fields.get(&43).unwrap(),
            "IDDQD Bank.                         GE"
        );
        assert_eq!(r.iso_fields.get(&48).unwrap(), "USRDT|2595100250");
        assert_eq!(r.iso_fields.get(&49).unwrap(), "643");
        assert_eq!(r.iso_fields.get(&51).unwrap(), "643");
        assert_eq!(r.iso_fields.get(&60).unwrap(), "3");
        assert_eq!(r.iso_fields.get(&101).unwrap(), "91926242");
        assert_eq!(r.iso_fields.get(&102).unwrap(), "2371492071643");
    }

    #[test]
    fn missing_saf() {
        let payload = r#"{
            "SRC": "M",
            "MTI": "0200"
        }"#;

        if SigmaRequest::from_json_value(serde_json::from_str(payload).unwrap()).is_ok() {
            unreachable!("Should not return Ok if mandatory field is missing");
        }
    }

    #[test]
    fn invalid_saf() {
        let payload = r#"{
        	"SAF": 1234,
            "SRC": "M",
            "MTI": "0200"
        }"#;

        if SigmaRequest::from_json_value(serde_json::from_str(payload).unwrap()).is_ok() {
            unreachable!("Should not return Ok if the filed has invalid format");
        }
    }

    #[test]
    fn missing_source() {
        let payload = r#"{
        	"SAF": "N",
            "MTI": "0200"
        }"#;

        if SigmaRequest::from_json_value(serde_json::from_str(payload).unwrap()).is_ok() {
            unreachable!("Should not return Ok if mandatory field is missing");
        }
    }

    #[test]
    fn invalid_source() {
        let payload = r#"{
        	"SAF": "N",
            "SRC": 929292,
            "MTI": "0200"
        }"#;

        if SigmaRequest::from_json_value(serde_json::from_str(payload).unwrap()).is_ok() {
            unreachable!("Should not return Ok if the filed has invalid format");
        }
    }

    #[test]
    fn missing_mti() {
        let payload = r#"{
        	"SAF": "N",
        	"SRC": "O"
        }"#;

        if SigmaRequest::from_json_value(serde_json::from_str(payload).unwrap()).is_ok() {
            unreachable!("Should not return Ok if mandatory field is missing");
        }
    }

    #[test]
    fn invalid_mti() {
        let payload = r#"{
        	"SAF": "N",
            "SRC": "O",
            "MTI": 1200
        }"#;

        if SigmaRequest::from_json_value(serde_json::from_str(payload).unwrap()).is_ok() {
            unreachable!("Should not return Ok if the filed has invalid format");
        }
    }

    #[test]
    fn generating_auth_serno() {
        let payload = r#"{
                "SAF": "Y",
                "SRC": "M",
                "MTI": "0200",
                "T0000": "02371492071643"
            }"#;

        let r: SigmaRequest =
            SigmaRequest::from_json_value(serde_json::from_str(payload).unwrap()).unwrap();
        assert!(
            r.auth_serno > 0,
            "Should generate authorization serno if the field is missing"
        );
    }

    #[test]
    fn encode_generated_auth_serno() {
        let payload = r#"{
                "SAF": "Y",
                "SRC": "M",
                "MTI": "0201",
                "Serno": 7877706965687192023
            }"#;

        let r: SigmaRequest =
            SigmaRequest::from_json_value(serde_json::from_str(payload).unwrap()).unwrap();
        let serialized = r.encode().unwrap();
        assert_eq!(
            serialized,
            b"00016YM02017877706965"[..],
            "Original auth serno should be trimmed to 10 bytes"
        );
    }

    #[test]
    fn encode_sigma_request() {
        let payload = r#"{
                "SAF": "Y",
                "SRC": "M",
                "MTI": "0200",
                "Serno": 6007040979,
                "T0000": 2371492071643,
                "T0001": "C",
                "T0002": 643,
                "T0003": "000100000000",
                "T0004": 978,
                "T0005": "000300000000",
                "T0006": "OPS6",
                "T0007": 19,
                "T0008": 643,
                "T0009": 3102,
                "T0010": 3104,
                "T0011": 2,
                "T0014": "IDDQD Bank",
                "T0016": 74707182,
                "T0018": "Y",
                "T0022": "000000000010",
                "i000": "0100",
                "i002": "555544******1111",
                "i003": "500000",
                "i004": "000100000000",
                "i006": "000100000000",
                "i007": "0629151748",
                "i011": "100250",
                "i012": "181748",
                "i013": "0629",
                "i018": "0000",
                "i022": "0000",
                "i025": "02",
                "i032": "010455",
                "i037": "002595100250",
                "i041": 990,
                "i042": "DCZ1",
                "i043": "IDDQD Bank.                         GE",
                "i048": "USRDT|2595100250",
                "i049": 643,
                "i051": 643,
                "i060": 3,
                "i101": 91926242,
                "i102": 2371492071643
            }"#;

        let r: SigmaRequest =
            SigmaRequest::from_json_value(serde_json::from_str(payload).unwrap()).unwrap();
        let serialized = r.encode().unwrap();
        assert_eq!(
            serialized,
            b"00536YM02006007040979T\x00\x00\x00\x00\x132371492071643T\x00\x01\x00\x00\x01CT\x00\x02\x00\x00\x03643T\x00\x03\x00\x00\x12000100000000T\x00\x04\x00\x00\x03978T\x00\x05\x00\x00\x12000300000000T\x00\x06\x00\x00\x04OPS6T\x00\x07\x00\x00\x0219T\x00\x08\x00\x00\x03643T\x00\t\x00\x00\x043102T\x00\x10\x00\x00\x043104T\x00\x11\x00\x00\x012T\x00\x14\x00\x00\x10IDDQD BankT\x00\x16\x00\x00\x0874707182T\x00\x18\x00\x00\x01YT\x00\x22\x00\x00\x12000000000010I\x00\x00\x00\x00\x040100I\x00\x02\x00\x00\x16555544******1111I\x00\x03\x00\x00\x06500000I\x00\x04\x00\x00\x12000100000000I\x00\x06\x00\x00\x12000100000000I\x00\x07\x00\x00\x100629151748I\x00\x11\x00\x00\x06100250I\x00\x12\x00\x00\x06181748I\x00\x13\x00\x00\x040629I\x00\x18\x00\x00\x040000I\x00\"\x00\x00\x040000I\x00%\x00\x00\x0202I\x002\x00\x00\x06010455I\x007\x00\x00\x12002595100250I\x00A\x00\x00\x03990I\x00B\x00\x00\x04DCZ1I\x00C\x00\x008IDDQD Bank.                         GEI\x00H\x00\x00\x16USRDT|2595100250I\x00I\x00\x00\x03643I\x00Q\x00\x00\x03643I\x00`\x00\x00\x013I\x01\x01\x00\x00\x0891926242I\x01\x02\x00\x00\x132371492071643"[..]
        );
    }

    #[test]
    fn decode_sigma_request() {
        let src = Bytes::from_static(b"00536YM02006007040979T\x00\x00\x00\x00\x132371492071643T\x00\x01\x00\x00\x01CT\x00\x02\x00\x00\x03643T\x00\x03\x00\x00\x12000100000000T\x00\x04\x00\x00\x03978T\x00\x05\x00\x00\x12000300000000T\x00\x06\x00\x00\x04OPS6T\x00\x07\x00\x00\x0219T\x00\x08\x00\x00\x03643T\x00\t\x00\x00\x043102T\x00\x10\x00\x00\x043104T\x00\x11\x00\x00\x012T\x00\x14\x00\x00\x10IDDQD BankT\x00\x16\x00\x00\x0874707182T\x00\x18\x00\x00\x01YT\x00\x22\x00\x00\x12000000000010I\x00\x00\x00\x00\x040100I\x00\x02\x00\x00\x16555544******1111I\x00\x03\x00\x00\x06500000I\x00\x04\x00\x00\x12000100000000I\x00\x06\x00\x00\x12000100000000I\x00\x07\x00\x00\x100629151748I\x00\x11\x00\x00\x06100250I\x00\x12\x00\x00\x06181748I\x00\x13\x00\x00\x040629I\x00\x18\x00\x00\x040000I\x00\"\x00\x00\x040000I\x00%\x00\x00\x0202I\x002\x00\x00\x06010455I\x007\x00\x00\x12002595100250I\x00A\x00\x00\x03990I\x00B\x00\x00\x04DCZ1I\x00C\x00\x008IDDQD Bank.                         GEI\x00H\x00\x00\x16USRDT|2595100250I\x00I\x00\x00\x03643I\x00Q\x00\x00\x03643I\x00`\x00\x00\x013I\x01\x01\x00\x00\x0891926242I\x01\x02\x00\x00\x132371492071643");
        let json = r#"{
                "SAF": "Y",
                "SRC": "M",
                "MTI": "0200",
                "Serno": 6007040979,
                "T0000": 2371492071643,
                "T0001": "C",
                "T0002": 643,
                "T0003": "000100000000",
                "T0004": 978,
                "T0005": "000300000000",
                "T0006": "OPS6",
                "T0007": 19,
                "T0008": 643,
                "T0009": 3102,
                "T0010": 3104,
                "T0011": 2,
                "T0014": "IDDQD Bank",
                "T0016": 74707182,
                "T0018": "Y",
                "T0022": "000000000010",
                "i000": "0100",
                "i002": "555544******1111",
                "i003": "500000",
                "i004": "000100000000",
                "i006": "000100000000",
                "i007": "0629151748",
                "i011": "100250",
                "i012": "181748",
                "i013": "0629",
                "i018": "0000",
                "i022": "0000",
                "i025": "02",
                "i032": "010455",
                "i037": "002595100250",
                "i041": 990,
                "i042": "DCZ1",
                "i043": "IDDQD Bank.                         GE",
                "i048": "USRDT|2595100250",
                "i049": 643,
                "i051": 643,
                "i060": 3,
                "i101": 91926242,
                "i102": 2371492071643
            }"#;

        let target: SigmaRequest =
            SigmaRequest::from_json_value(serde_json::from_str(json).unwrap()).unwrap();

        let req = SigmaRequest::decode(src).unwrap();

        assert_eq!(req, target);
    }

    #[test]
    fn decode_sigma_response() {
        let s = Bytes::from_static(b"0002401104007040978T\x00\x31\x00\x00\x048495");

        let resp = SigmaResponse::decode(s).unwrap();
        assert_eq!(resp.mti, "0110");
        assert_eq!(resp.auth_serno, 4007040978);
        assert_eq!(resp.reason, 8495);

        let serialized = serde_json::to_string(&resp).unwrap();
        assert_eq!(
            serialized,
            r#"{"mti":"0110","auth_serno":4007040978,"reason":8495}"#
        );
    }

    #[test]
    fn decode_sigma_response_incorrect_auth_serno() {
        let s = Bytes::from_static(b"000250110XYZ7040978T\x00\x31\x00\x00\x048100");

        assert!(SigmaResponse::decode(s).is_err());
    }

    #[test]
    fn decode_sigma_response_incorrect_reason() {
        let s = Bytes::from_static(b"0002501104007040978T\x00\x31\x00\x00\x04ABCD");

        assert!(SigmaResponse::decode(s).is_err());
    }

    #[test]
    fn decode_sigma_response_fee_data() {
        let s = Bytes::from_static(
            b"0004001104007040978T\x00\x31\x00\x00\x048100T\x00\x32\x00\x00\x108116978300",
        );

        let resp = SigmaResponse::decode(s).unwrap();
        assert_eq!(resp.mti, "0110");
        assert_eq!(resp.auth_serno, 4007040978);
        assert_eq!(resp.reason, 8100);

        let serialized = serde_json::to_string(&resp).unwrap();
        assert_eq!(
            serialized,
            r#"{"mti":"0110","auth_serno":4007040978,"reason":8100,"fees":[{"reason":8116,"currency":978,"amount":300}]}"#
        );
    }

    #[test]
    fn decode_sigma_response_correct_short_auth_serno() {
        let s = Bytes::from_static(b"000240110123123    T\x00\x31\x00\x00\x048100");

        let resp = SigmaResponse::decode(s).unwrap();
        assert_eq!(resp.mti, "0110");
        assert_eq!(resp.auth_serno, 123123);
        assert_eq!(resp.reason, 8100);

        let serialized = serde_json::to_string(&resp).unwrap();
        assert_eq!(
            serialized,
            r#"{"mti":"0110","auth_serno":123123,"reason":8100}"#
        );
    }

    #[test]
    fn decode_fee_data() {
        let data = b"8116978300";

        let fee = FeeData::from_slice(data).unwrap();
        assert_eq!(fee.reason, 8116);
        assert_eq!(fee.currency, 978);
        assert_eq!(fee.amount, 300);
    }

    #[test]
    fn decode_fee_data_large_amount() {
        let data = b"8116643123456789";

        let fee = FeeData::from_slice(data).unwrap();
        assert_eq!(fee.reason, 8116);
        assert_eq!(fee.currency, 643);
        assert_eq!(fee.amount, 123456789);
    }

    #[test]
    fn decode_sigma_response_fee_data_additional_data() {
        let s = Bytes::from_static(b"0015201104007040978T\x00\x31\x00\x00\x048100T\x00\x32\x00\x00\x1181166439000T\x00\x48\x00\x01\x05CJyuARCDBRibpKn+BSIVCgx0ZmE6FwAAAKoXmwIQnK4BGLcBIhEKDHRmcDoWAAAAxxX+ARik\nATCBu4PdBToICKqv7BQQgwVAnK4BSAI=");

        let resp = SigmaResponse::decode(s).unwrap();
        assert_eq!(resp.mti, "0110");
        assert_eq!(resp.auth_serno, 4007040978);
        assert_eq!(resp.reason, 8100);

        let serialized = serde_json::to_string(&resp).unwrap();
        assert_eq!(
            serialized,
            r#"{"mti":"0110","auth_serno":4007040978,"reason":8100,"fees":[{"reason":8116,"currency":643,"amount":9000}],"adata":"CJyuARCDBRibpKn+BSIVCgx0ZmE6FwAAAKoXmwIQnK4BGLcBIhEKDHRmcDoWAAAAxxX+ARik\nATCBu4PdBToICKqv7BQQgwVAnK4BSAI="}"#
        );
    }

    #[test]
    fn encode_fee_data() {
        let fee_data = FeeData {
            reason: 8123,
            currency: 643,
            amount: 1234567890,
        };

        assert_eq!(fee_data.encode().unwrap()[..], b"81236431234567890"[..]);
    }

    #[test]
    fn encode_fee_data_incorrect() {
        assert!(FeeData {
            reason: 10000,
            currency: 643,
            amount: 1234567890,
        }
        .encode()
        .is_err());

        assert!(FeeData {
            reason: 8123,
            currency: 6430,
            amount: 1234567890,
        }
        .encode()
        .is_err());
    }

    #[test]
    fn encode_sigma_response_fee_data_additional_data() {
        let src = r#"{"mti":"0110","auth_serno":4007040978,"reason":8100,"fees":[{"reason":8116,"currency":643,"amount":9000}],"adata":"CJyuARCDBRibpKn+BSIVCgx0ZmE6FwAAAKoXmwIQnK4BGLcBIhEKDHRmcDoWAAAAxxX+ARik\nATCBu4PdBToICKqv7BQQgwVAnK4BSAI="}"#;
        let response = serde_json::from_str::<SigmaResponse>(src).unwrap();

        let target = b"0015201104007040978T\x00\x31\x00\x00\x048100T\x00\x32\x00\x00\x1181166439000T\x00\x48\x00\x01\x05CJyuARCDBRibpKn+BSIVCgx0ZmE6FwAAAKoXmwIQnK4BGLcBIhEKDHRmcDoWAAAAxxX+ARik\nATCBu4PdBToICKqv7BQQgwVAnK4BSAI=";
        assert_eq!(response.encode().unwrap()[..], target[..])
    }

    #[test]
    fn validate_saf_field() {
        assert!(validate_saf("Y").is_ok());
        assert!(validate_saf("N").is_ok());

        assert!(validate_saf("").is_err());
        assert!(validate_saf("YY").is_err());
        assert!(validate_saf("NN").is_err());
        assert!(validate_saf("A").is_err());
    }

    #[test]
    fn validate_source_field() {
        assert!(validate_source("Y").is_ok());
        assert!(validate_source("N").is_ok());

        assert!(validate_source("").is_err());
        assert!(validate_source("YY").is_err());
        assert!(validate_source("NN").is_err());
    }

    #[test]
    fn validate_mti_field() {
        assert!(validate_mti("0120").is_ok());

        assert!(validate_mti("").is_err());
        assert!(validate_mti("120").is_err());
        assert!(validate_mti("00120").is_err());
        assert!(validate_mti("O120").is_err());
    }
}
