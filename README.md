# extfg-sigma

Rust community library for serializaing/deserializing Sigma extfg financial messages.

### Usage
```toml
[dependencies]
extfg-sigma = "0.1"
```

```rust
use extfg_sigma::{SigmaRequest};

let s = r#"{
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

// Deserializing request
let req = SPRequest::new(s.as_bytes());
println!("{:?}", req);

// Serializing request
let msg : String = req.serialize().unwrap();

// Sending the data over TCP stream:
s.write_all(&msg.as_bytes()).await?;
```

Check [lakgves](https://github.com/timgabets/lakgves) for more examples.