use crate::util::{msg_len, serialize_tag, TagType};
use serde::Serialize;
use serde_json::Value;
use std::convert::TryInto;
use std::io;

use bytes::{BufMut, BytesMut};
use std::collections::BTreeMap;

mod util;

#[derive(Serialize, Debug)]
pub struct SigmaRequest {
    saf: String,
    source: String,
    mti: String,
    auth_serno: u64,
    tags: BTreeMap<usize, String>,
    iso_fields: BTreeMap<usize, String>,
}

impl SigmaRequest {
    pub fn new(data: Value) -> Result<SigmaRequest, io::ErrorKind> {
        let mut req = SigmaRequest {
            saf: String::from("N"),
            source: String::from("X"),
            mti: String::from("0100"),
            auth_serno: 0,
            tags: BTreeMap::new(),
            iso_fields: BTreeMap::new(),
        };

        // SAF
        let mut f = "SAF";
        match data.get(f) {
            Some(opt) => {
                match opt.as_str() {
                    Some(v) => {
                        req.saf = v.to_string();
                    }
                    None => {
                        println!("Incoming request has invalid {} field data format - should be a String", f);
                        return Err(io::ErrorKind::InvalidData);
                    }
                }
            }
            None => {
                println!("Incoming request has missing mandatory {} field", f);
                return Err(io::ErrorKind::InvalidInput);
            }
        }

        // Source
        f = "SRC";
        match data.get(f) {
            Some(opt) => {
                match opt.as_str() {
                    Some(v) => {
                        req.source = v.to_string();
                    }
                    None => {
                        println!("Incoming request has invalid {} field data format - should be a String", f);
                        return Err(io::ErrorKind::InvalidData);
                    }
                }
            }
            None => {
                println!("Incoming request has missing mandatory {} field", f);
                return Err(io::ErrorKind::InvalidInput);
            }
        }

        // Source
        f = "MTI";
        match data.get(f) {
            Some(opt) => {
                match opt.as_str() {
                    Some(v) => {
                        req.mti = v.to_string();
                    }
                    None => {
                        println!("Incoming request has invalid {} field data format - should be a String", f);
                        return Err(io::ErrorKind::InvalidData);
                    }
                }
            }
            None => {
                println!("Incoming request has missing mandatory {} field", f);
                return Err(io::ErrorKind::InvalidInput);
            }
        }

        // Authorization serno
        f = "Serno";
        match data.get(f) {
            Some(opt) => match opt.as_str() {
                Some(v) => {
                    req.auth_serno = v.parse::<u64>().unwrap();
                }
                None => {
                    // Not a string
                    match opt.as_u64() {
                        Some(v) => {
                            req.auth_serno = v;
                        }
                        None => {
                            // Neither a string nor a u64
                            println!(
                                "Incoming request has invalid {} field data format - should be u64 ot string",
                                f
                            );
                            return Err(io::ErrorKind::InvalidData);
                        }
                    }
                }
            },
            None => {
                req.auth_serno = util::gen_auth_serno();
            }
        }

        // Tags
        for i in 0..23 {
            let id = format!("T{:04}", i);
            if let Some(tag) = data.get(id) {
                match tag.as_str() {
                    Some(v) => {
                        req.tags.insert(i, v.to_string());
                    }
                    None => match tag.as_u64() {
                        Some(v) => {
                            req.tags.insert(i, v.to_string());
                        }
                        None => {
                            println!("Incoming request has invalid {} field data format - should be either String or u64", format!("T{:04}", i));
                            return Err(io::ErrorKind::InvalidData);
                        }
                    },
                }
            }
        }

        // ISO Fields
        for i in 0..128 {
            let id = format!("i{:03}", i);
            if let Some(tag) = data.get(id) {
                match tag.as_str() {
                    Some(v) => {
                        req.iso_fields.insert(i, v.to_string());
                    }
                    None => match tag.as_u64() {
                        Some(v) => {
                            req.iso_fields.insert(i, v.to_string());
                        }
                        None => {
                            println!("Incoming request has invalid {} field data format - should be either String or u64", format!("i{:03}", i));
                            return Err(io::ErrorKind::InvalidData);
                        }
                    },
                }
            }
        }

        Ok(req)
    }

    pub fn serialize(&self) -> Result<BytesMut, String> {
        let mut buf = BytesMut::with_capacity(8192);
        buf.put(self.saf.as_bytes());
        buf.put(self.source.as_bytes());
        buf.put(self.mti.as_bytes());
        let mut auth_serno = self.auth_serno.to_string();
        if auth_serno.len() > 10 {
            auth_serno.truncate(10);
        } else {
            auth_serno = format!("{:010}", auth_serno);
        }

        buf.put(auth_serno.as_bytes());

        for key in self.tags.keys() {
            buf.put(serialize_tag(
                TagType::Regular,
                *key,
                self.tags[key].as_str(),
            ));
        }

        for key in self.iso_fields.keys() {
            buf.put(serialize_tag(
                TagType::Iso,
                *key,
                self.iso_fields[key].as_str(),
            ));
        }

        // Appending message length
        let mut serialized = BytesMut::with_capacity(8192);
        serialized.put(msg_len(buf.len()));
        serialized.put(buf);

        Ok(serialized.split())
    }
}

#[derive(Serialize, Debug)]
pub struct FeeData {
    reason: i32,
    currency: i32,
    amount: i64,
}

impl FeeData {
    pub fn new(data: &[u8], data_len: usize) -> Self {
        let mut reason = -1;
        let mut currency = -1;
        let mut amount = -1;

        if data_len >= 8 {
            // "\x00\x32\x00\x00\x108116978300"
            reason = match String::from_utf8_lossy(&data[0..4]).parse() {
                Ok(r) => r,
                Err(_) => -1,
            };

            currency = match String::from_utf8_lossy(&data[4..7]).parse() {
                Ok(r) => r,
                Err(_) => -1,
            };

            amount = match String::from_utf8_lossy(&data[7..data_len]).parse() {
                Ok(r) => r,
                Err(_) => -1,
            };
        } else {
            println!("FeeData length error: {:?}", data_len);
        };

        FeeData {
            reason,
            currency,
            amount,
        }
    }
}

fn pop(x: &[u8]) -> &[u8; 2] {
    x.try_into().expect("slice with incorrect length")
}

#[derive(Serialize, Debug)]
pub struct SigmaResponse {
    mti: String,
    auth_serno: i64,
    reason: i32,
    // TODO: Fees
}

impl SigmaResponse {
    pub fn new(s: &[u8]) -> Self {
        let mut reason = -1;

        let mut from: usize = 0;
        let mut to: usize = 5;
        let data_len = match String::from_utf8_lossy(&s[from..to]).parse::<usize>() {
            Ok(r) => r + 5,
            Err(_) => 0,
        };

        from = 5;
        to = 9;
        if data_len < from || data_len < from {
            println!(
                "Out of boundaries error: data length is {:?}, but trying to access [{:?}..{:?}]",
                data_len, from, to
            );
            // TODO: exit or something
        }

        let mti = &s[from..to];

        from = 9;
        to = 19;
        if data_len < from || data_len < from {
            println!(
                "Out of boundaries error: data length is {:?}, but trying to access [{:?}..{:?}]",
                data_len, from, to
            );
            // TODO: exit or something
        }
        let auth_serno = match String::from_utf8_lossy(&s[from..to])
            .split_whitespace()
            .map(|s| s.parse::<i64>())
            .next()
        {
            Some(Ok(r)) => r,
            Some(Err(_)) => -1,
            None => -1,
        };

        // let s = b"0004001104007040978T\x00\x31\x00\x00\x048100T\x00\x32\x00\x00\x108116978300";
        // 01104007040978T.....8100T.....8116978300
        let indx = 19;
        let tag_start = indx;
        let tag_end = tag_start + 4;
        if &s[tag_start..tag_end] == b"T\x00\x31\x00" {
            // Tag T0031

            let tag_data_len = u16::from_be_bytes(*pop(&s[tag_end..tag_end + 2]));
            let tag_data_start = tag_end + 2;
            let tag_data_end = tag_data_start + tag_data_len as usize;

            reason = match String::from_utf8_lossy(&s[tag_data_start..tag_data_end]).parse() {
                Ok(r) => r,
                Err(_) => -1,
            };
        }

        SigmaResponse {
            mti: String::from_utf8_lossy(mti).to_string(),
            auth_serno,
            reason,
        }
    }

    pub fn serialize(&self) -> Result<String, serde_json::error::Error> {
        let serialized = serde_json::to_string(&self)?;
        Ok(serialized)
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

        let r: SigmaRequest = SigmaRequest::new(serde_json::from_str(&payload).unwrap()).unwrap();
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

        let r: SigmaRequest = SigmaRequest::new(serde_json::from_str(&payload).unwrap()).unwrap();
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

        if SigmaRequest::new(serde_json::from_str(&payload).unwrap()).is_ok() {
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

        if SigmaRequest::new(serde_json::from_str(&payload).unwrap()).is_ok() {
            unreachable!("Should not return Ok if the filed has invalid format");
        }
    }

    #[test]
    fn missing_source() {
        let payload = r#"{
        	"SAF": "N",
            "MTI": "0200"
        }"#;

        if SigmaRequest::new(serde_json::from_str(&payload).unwrap()).is_ok() {
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

        if SigmaRequest::new(serde_json::from_str(&payload).unwrap()).is_ok() {
            unreachable!("Should not return Ok if the filed has invalid format");
        }
    }

    #[test]
    fn missing_mti() {
        let payload = r#"{
        	"SAF": "N",
        	"SRC": "O"
        }"#;

        if SigmaRequest::new(serde_json::from_str(&payload).unwrap()).is_ok() {
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

        if SigmaRequest::new(serde_json::from_str(&payload).unwrap()).is_ok() {
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

        let r: SigmaRequest = SigmaRequest::new(serde_json::from_str(&payload).unwrap()).unwrap();
        assert!(
            r.auth_serno > 0,
            "Should generate authorization serno if the field is missing"
        );
    }

    #[test]
    fn serializing_generated_auth_serno() {
        let payload = r#"{
                "SAF": "Y",
                "SRC": "M",
                "MTI": "0201",
                "Serno": 7877706965687192023
            }"#;

        let r: SigmaRequest = SigmaRequest::new(serde_json::from_str(&payload).unwrap()).unwrap();
        let serialized = r.serialize().unwrap();
        assert_eq!(
            serialized,
            b"00016YM02017877706965"[..],
            "Original auth serno should be trimmed to 10 bytes"
        );
    }

    #[test]
    fn serializing_ok() {
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

        let r: SigmaRequest = SigmaRequest::new(serde_json::from_str(&payload).unwrap()).unwrap();
        let serialized = r.serialize().unwrap();
        assert_eq!(
            serialized,
            b"00536YM02006007040979T\x00\x00\x00\x00\x132371492071643T\x00\x01\x00\x00\x01CT\x00\x02\x00\x00\x03643T\x00\x03\x00\x00\x12000100000000T\x00\x04\x00\x00\x03978T\x00\x05\x00\x00\x12000300000000T\x00\x06\x00\x00\x04OPS6T\x00\x07\x00\x00\x0219T\x00\x08\x00\x00\x03643T\x00\t\x00\x00\x043102T\x00\x10\x00\x00\x043104T\x00\x11\x00\x00\x012T\x00\x14\x00\x00\x10IDDQD BankT\x00\x16\x00\x00\x0874707182T\x00\x18\x00\x00\x01YT\x00\x22\x00\x00\x12000000000010I\x00\x00\x00\x00\x040100I\x00\x02\x00\x00\x16555544******1111I\x00\x03\x00\x00\x06500000I\x00\x04\x00\x00\x12000100000000I\x00\x06\x00\x00\x12000100000000I\x00\x07\x00\x00\x100629151748I\x00\x11\x00\x00\x06100250I\x00\x12\x00\x00\x06181748I\x00\x13\x00\x00\x040629I\x00\x18\x00\x00\x040000I\x00\"\x00\x00\x040000I\x00%\x00\x00\x0202I\x002\x00\x00\x06010455I\x007\x00\x00\x12002595100250I\x00A\x00\x00\x03990I\x00B\x00\x00\x04DCZ1I\x00C\x00\x008IDDQD Bank.                         GEI\x00H\x00\x00\x16USRDT|2595100250I\x00I\x00\x00\x03643I\x00Q\x00\x00\x03643I\x00`\x00\x00\x013I\x01\x01\x00\x00\x0891926242I\x01\x02\x00\x00\x132371492071643"[..]
        );
    }

    #[test]
    fn sigma_response_new() {
        let s = b"0002501104007040978T\x00\x31\x00\x00\x048495";

        let resp = SigmaResponse::new(s);
        assert_eq!(resp.mti, "0110");
        assert_eq!(resp.auth_serno, 4007040978);
        assert_eq!(resp.reason, 8495);

        let serialized = resp.serialize().unwrap();
        assert_eq!(
            serialized,
            r#"{"mti":"0110","auth_serno":4007040978,"reason":8495}"#
        );
    }

    #[test]
    fn sigma_response_incorrect_auth_serno() {
        let s = b"000250110XYZ7040978T\x00\x31\x00\x00\x048100";

        let resp = SigmaResponse::new(s);
        assert_eq!(resp.mti, "0110");
        assert_eq!(resp.auth_serno, -1);
        assert_eq!(resp.reason, 8100);

        let serialized = resp.serialize().unwrap();
        assert_eq!(
            serialized,
            r#"{"mti":"0110","auth_serno":-1,"reason":8100}"#
        );
    }

    #[test]
    fn sigma_response_incorrect_reason() {
        let s = b"0002501104007040978T\x00\x31\x00\x00\x04ABCD";

        let resp = SigmaResponse::new(s);
        assert_eq!(resp.mti, "0110");
        assert_eq!(resp.auth_serno, 4007040978);
        assert_eq!(resp.reason, -1);

        let serialized = resp.serialize().unwrap();
        assert_eq!(
            serialized,
            r#"{"mti":"0110","auth_serno":4007040978,"reason":-1}"#
        );
    }

    #[test]
    fn sigma_response_fee_data() {
        let s = b"0004001104007040978T\x00\x31\x00\x00\x048100T\x00\x32\x00\x00\x108116978300";

        let resp = SigmaResponse::new(s);
        assert_eq!(resp.mti, "0110");
        assert_eq!(resp.auth_serno, 4007040978);
        assert_eq!(resp.reason, 8100);

        let serialized = resp.serialize().unwrap();
        assert_eq!(
            serialized,
            r#"{"mti":"0110","auth_serno":4007040978,"reason":8100}"#
        );
    }

    #[test]
    fn sigma_response_correct_short_auth_serno() {
        let s = b"000400110123123    T\x00\x31\x00\x00\x048100";

        let resp = SigmaResponse::new(s);
        assert_eq!(resp.mti, "0110");
        assert_eq!(resp.auth_serno, 123123);
        assert_eq!(resp.reason, 8100);

        let serialized = resp.serialize().unwrap();
        assert_eq!(
            serialized,
            r#"{"mti":"0110","auth_serno":123123,"reason":8100}"#
        );
    }

    #[test]
    fn fee_data() {
        let data = b"8116978300";

        let fee = FeeData::new(data, 10);
        assert_eq!(fee.reason, 8116);
        assert_eq!(fee.currency, 978);
        assert_eq!(fee.amount, 300);
    }

    #[test]
    fn fee_data_large_amount() {
        let data = b"8116643123456789";

        let fee = FeeData::new(data, 16);
        assert_eq!(fee.reason, 8116);
        assert_eq!(fee.currency, 643);
        assert_eq!(fee.amount, 123456789);
    }
}
