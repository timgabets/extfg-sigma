//use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::io;

use std::collections::BTreeMap;

mod util;

#[derive(Debug)]
pub struct SigmaRequest {
    saf: String,
    source: String,
    mti: String,
    auth_serno: u64,
    tags: BTreeMap<usize, String>,
    //iso_fields: BTreeMap<String, String>,
}

impl SigmaRequest {
    pub fn new(data: Value) -> Result<SigmaRequest, io::ErrorKind> {
        let mut req = SigmaRequest {
            saf: String::from("N"),
            source: String::from("X"),
            mti: String::from("0100"),
            auth_serno: 0,
            tags: BTreeMap::new(),
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
            Some(opt) => match opt.as_u64() {
                Some(v) => {
                    req.auth_serno = v;
                }
                None => {
                    println!(
                        "Incoming request has invalid {} field data format - should be u64",
                        f
                    );
                    return Err(io::ErrorKind::InvalidData);
                }
            },
            None => {
                req.auth_serno = util::gen_auth_serno();
            }
        }

        // Tags
        for i in 0..23 {
            let id = format!("T{:04}", i);
            match data.get(id) {
                Some(tag) => match tag.as_str() {
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
                },
                None => {}
            }
        }

        // ISO Fields
        

        Ok(req)
    }

    pub fn serialize(&self) -> Result<String, String> {
        Ok("Iddqd".to_string())
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
            "T0022": "000000000010"
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

        match r.tags.get(&12) {
            Some(_) => assert!(false),
            None => assert!(true),
        }

        match r.tags.get(&13) {
            Some(_) => assert!(false),
            None => assert!(true),
        }

        assert_eq!(r.tags.get(&14).unwrap(), "IDDQD Bank");

        match r.tags.get(&15) {
            Some(_) => assert!(false),
            None => assert!(true),
        }

        assert_eq!(r.tags.get(&16).unwrap(), "74707182");
        match r.tags.get(&17) {
            Some(_) => assert!(false),
            None => assert!(true),
        }
        assert_eq!(r.tags.get(&18).unwrap(), "Y");
        assert_eq!(r.tags.get(&22).unwrap(), "000000000010");
    }

    #[test]
    fn missing_saf() {
        let payload = r#"{
            "SRC": "M",
            "MTI": "0200"
        }"#;

        match SigmaRequest::new(serde_json::from_str(&payload).unwrap()) {
            Ok(_) => assert!(false, "Should not return Ok if mandatory field is missing"),
            Err(_) => assert!(true),
        }
    }

    #[test]
    fn invalid_saf() {
        let payload = r#"{
        	"SAF": 1234,
            "SRC": "M",
            "MTI": "0200"
        }"#;

        match SigmaRequest::new(serde_json::from_str(&payload).unwrap()) {
            Ok(_) => assert!(
                false,
                "Should not return Ok if the filed has invalid format"
            ),
            Err(_) => assert!(true),
        }
    }

    #[test]
    fn missing_source() {
        let payload = r#"{
        	"SAF": "N",
            "MTI": "0200"
        }"#;

        match SigmaRequest::new(serde_json::from_str(&payload).unwrap()) {
            Ok(_) => assert!(false, "Should not return Ok if mandatory field is missing"),
            Err(_) => assert!(true),
        }
    }

    #[test]
    fn invalid_source() {
        let payload = r#"{
        	"SAF": "N",
            "SRC": 929292,
            "MTI": "0200"
        }"#;

        match SigmaRequest::new(serde_json::from_str(&payload).unwrap()) {
            Ok(_) => assert!(
                false,
                "Should not return Ok if the filed has invalid format"
            ),
            Err(_) => assert!(true),
        }
    }

    #[test]
    fn missing_mti() {
        let payload = r#"{
        	"SAF": "N",
        	"SRC": "O"
        }"#;

        match SigmaRequest::new(serde_json::from_str(&payload).unwrap()) {
            Ok(_) => assert!(false, "Should not return Ok if mandatory field is missing"),
            Err(_) => assert!(true),
        }
    }

    #[test]
    fn invalid_mti() {
        let payload = r#"{
        	"SAF": "N",
            "SRC": "O",
            "MTI": 1200
        }"#;

        match SigmaRequest::new(serde_json::from_str(&payload).unwrap()) {
            Ok(_) => assert!(
                false,
                "Should not return Ok if the filed has invalid format"
            ),
            Err(_) => assert!(true),
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
}
