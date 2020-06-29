//use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::io;

//use std::collections::BTreeMap;

#[derive(Debug)]
pub struct SigmaRequest {
    saf: String,
    source: String,
    mti: String,
    auth_serno: u64,
    //tags: BTreeMap<String, String>,
    //iso_fields: BTreeMap<String, String>,
}

impl SigmaRequest {
    pub fn new(data: Value) -> Result<SigmaRequest, io::ErrorKind> {
        let mut req = SigmaRequest {
            saf: String::from("N"),
            source: String::from("X"),
            mti: String::from("0100"),
            auth_serno: 0,
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

        // TODO: unwrapping unwrappable unwraps:
        req.auth_serno = data.get("Serno").unwrap().as_u64().unwrap();

        // TODO: gen_auth_serno()
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
    fn dummy() {
        let payload = r#"{
            "SAF": "Y",
            "SRC": "M",
            "MTI": "0200",
            "Serno": 6007040979,
            "T0000": "02371492071643",
            "T0001": "C",
            "T0002": "643",
            "T0003": "000100000000",
            "T0004": "643",
            "T0005": "000100000000",
            "T0006": "OPS6",
            "T0007": "19",
            "T0008": "643",
            "T0009": "3104",
            "T0010": "3104",
            "T0011": "2",
            "T0014": "IDDQD Bank",
            "T0016": "74707182",
            "T0018": "Y",
            "T0022": "000000000000"
        }"#;

        let r: SigmaRequest = SigmaRequest::new(serde_json::from_str(&payload).unwrap()).unwrap();
        assert_eq!(r.saf, "Y");
        assert_eq!(r.source, "M");
        assert_eq!(r.mti, "0200");
        assert_eq!(r.auth_serno, 6007040979);
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
}
