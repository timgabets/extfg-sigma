use bytes::{Bytes, BytesMut};
use rand::Rng;
use std::fmt::{Display, Formatter, Result as FmtResult};

use super::Error;

macro_rules! parse_ascii_bytes_lossy {
    ($b:expr, $t:ty, $err:expr) => {
        String::from_utf8_lossy($b).parse::<$t>().map_err(|_| $err)
    };
}

pub(crate) fn bytes_split_to(bytes: &mut Bytes, at: usize) -> Result<Bytes, Error> {
    let len = bytes.len();

    if len < at {
        return Err(Error::Bounds(format!(
            "split_to out of bounds: {:?} <= {:?}",
            at,
            bytes.len(),
        )));
    }

    Ok(bytes.split_to(at))
}

/// Generate Authorization Serno
pub fn gen_random_auth_serno() -> u64 {
    let mut rng = rand::thread_rng();
    let rrn: u64 = rng.gen();
    rrn
}

pub(crate) fn decode_bcd_x2(v: u8) -> Result<u8, Error> {
    let left = v >> 4;
    if !matches!(left, 0..=9) {
        return Err(Error::Bounds(format!(
            "Left bits is not in [0,9] range: {:X}",
            v
        )));
    }

    let right = v & 0x0f;
    if !matches!(right, 0..=9) {
        return Err(Error::Bounds(format!(
            "Right bits is not in [0,9] range: {:X}",
            v
        )));
    }

    Ok(left * 10 + right)
}

pub(crate) fn decode_bcd_x4(v: &[u8; 2]) -> Result<u16, Error> {
    let l = decode_bcd_x2(v[0])?;
    let r = decode_bcd_x2(v[1])?;
    Ok(l as u16 * 100 + r as u16)
}

pub(crate) fn encode_bcd_x2(v: u8) -> Result<u8, Error> {
    if v > 99 {
        return Err(Error::Bounds(format!(
            "u8 '{}' contains more than 2 digits",
            v
        )));
    }

    Ok(((v / 10) << 4) + (v % 10))
}

pub(crate) fn encode_bcd_x4(v: u16) -> Result<[u8; 2], Error> {
    if v > 9999 {
        return Err(Error::Bounds(format!(
            "u16 '{}' contains more than 4 digits",
            v
        )));
    }

    let digit_0 = (v % 10) as u8;
    let digit_1 = ((v / 10) % 10) as u8;
    let digit_2 = ((v / 100) % 10) as u8;
    let digit_3 = ((v / 1000) % 10) as u8;

    let left = (digit_3 << 4) + digit_2;
    let right = (digit_1 << 4) + digit_0;

    Ok([left, right])
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Tag {
    Regular(u16),
    Iso(u16),
    IsoSubfield(u16, u8),
}

impl Tag {
    pub fn encode_to_buf(&self, buf: &mut BytesMut) -> Result<(), Error> {
        match self {
            Self::Regular(i) => {
                buf.extend_from_slice(&b"T"[..]);
                buf.extend_from_slice(&encode_bcd_x4(*i)?[..]);
                buf.extend_from_slice(&[0]);
            }
            Self::Iso(i) => {
                buf.extend_from_slice(&b"I"[..]);
                buf.extend_from_slice(&encode_bcd_x4(*i)?[..]);
                buf.extend_from_slice(&[0]);
            }
            Self::IsoSubfield(i, si) => {
                buf.extend_from_slice(&b"S"[..]);
                buf.extend_from_slice(&encode_bcd_x4(*i)?[..]);
                buf.extend_from_slice(&[encode_bcd_x2(*si)?]);
            }
        }
        Ok(())
    }

    pub fn decode(data: Bytes) -> Result<Self, Error> {
        if data.len() < 4 {
            return Err(Error::IncorrectTag("Should be 5 bytes long".into()));
        }
        let i = decode_bcd_x4(&[data[1], data[2]])?;
        let si = decode_bcd_x2(data[3])?;
        match data[0] {
            b'T' => Ok(Tag::Regular(i)),
            b'I' => Ok(Tag::Iso(i)),
            b'S' => Ok(Tag::IsoSubfield(i, si)),
            _ => Err(Error::IncorrectTag("Unknown kind".to_string())),
        }
    }

    pub fn from_str(s: &str) -> Result<Self, Error> {
        let bytes = s.as_bytes();
        match (bytes.get(0), s.len()) {
            (Some(b'T'), 5) | (Some(b't'), 5) => {
                let v = parse_ascii_bytes_lossy!(
                    &bytes[1..5],
                    u16,
                    Error::IncorrectTag("incorrect format for T".into())
                )?;
                Ok(Self::Regular(v))
            }
            (Some(b'I'), 4) | (Some(b'i'), 4) => {
                let v = parse_ascii_bytes_lossy!(
                    &bytes[1..4],
                    u16,
                    Error::IncorrectTag("incorrect format for i".into())
                )?;
                Ok(Self::Iso(v))
            }
            (Some(b'S'), 7) | (Some(b's'), 7) => {
                let v = parse_ascii_bytes_lossy!(
                    &bytes[1..5],
                    u16,
                    Error::IncorrectTag("incorrect format for S".into())
                )?;
                let sv = parse_ascii_bytes_lossy!(
                    &bytes[5..7],
                    u8,
                    Error::IncorrectTag("incorrect format for S".into())
                )?;
                Ok(Self::IsoSubfield(v, sv))
            }
            (None, _) => Err(Error::IncorrectTag("Empty".into())),
            (Some(c), l) => Err(Error::IncorrectTag(format!(
                "Starts with: '{}', length: {}",
                c, l
            ))),
        }
    }
}

impl Display for Tag {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            Tag::Regular(i) => f.write_fmt(format_args!("T{:04}", i)),
            Tag::Iso(i) => f.write_fmt(format_args!("i{:03}", i)),
            Tag::IsoSubfield(i, si) => f.write_fmt(format_args!("s{:04}{:02}", i, si)),
        }
    }
}

pub fn encode_field_to_buf(tag: Tag, data: &[u8], buf: &mut BytesMut) -> Result<(), Error> {
    tag.encode_to_buf(buf)?;
    buf.extend_from_slice(&encode_bcd_x4(data.len() as u16)?[..]);
    buf.extend_from_slice(data);
    Ok(())
}

pub fn decode_field_from_cursor(buf: &mut Bytes) -> Result<(Tag, Bytes), Error> {
    let tag_src = bytes_split_to(buf, 4)?;
    let tag = Tag::decode(tag_src)?;

    let len_src = bytes_split_to(buf, 2)?;
    let len = decode_bcd_x4(&[len_src[0], len_src[1]])?;

    let data = bytes_split_to(buf, len as usize)?;
    Ok((tag, data))
}

#[cfg(test)]
mod tests {
    use bytes::BytesMut;

    use super::*;

    #[test]
    fn test_decode_bcd_x4() {
        assert_eq!(decode_bcd_x4(b"\x00\x01"), Ok(1));
        assert_eq!(decode_bcd_x4(b"\x00\x02"), Ok(2));
        assert_eq!(decode_bcd_x4(b"\x00\x03"), Ok(3));
        assert_eq!(decode_bcd_x4(b"\x00\x04"), Ok(4));
        assert_eq!(decode_bcd_x4(b"\x00\x05"), Ok(5));
        assert_eq!(decode_bcd_x4(b"\x00\x06"), Ok(6));
        assert_eq!(decode_bcd_x4(b"\x00\x07"), Ok(7));
        assert_eq!(decode_bcd_x4(b"\x00\x08"), Ok(8));
        assert_eq!(decode_bcd_x4(b"\x00\x09"), Ok(9));
        assert_eq!(decode_bcd_x4(b"\x00\x10"), Ok(10));
        assert_eq!(decode_bcd_x4(b"\x00\x11"), Ok(11));
        assert_eq!(decode_bcd_x4(b"\x00\x12"), Ok(12));
        assert_eq!(decode_bcd_x4(b"\x00\x13"), Ok(13));
        assert_eq!(decode_bcd_x4(b"\x00\x14"), Ok(14));
        assert_eq!(decode_bcd_x4(b"\x00\x15"), Ok(15));
        assert_eq!(decode_bcd_x4(b"\x00\x16"), Ok(16));
        assert_eq!(decode_bcd_x4(b"\x00\x17"), Ok(17));
        assert_eq!(decode_bcd_x4(b"\x00\x18"), Ok(18));
        assert_eq!(decode_bcd_x4(b"\x00\x19"), Ok(19));
        assert_eq!(decode_bcd_x4(b"\x00\x20"), Ok(20));
        assert_eq!(decode_bcd_x4(b"\x00\x21"), Ok(21));
        assert_eq!(decode_bcd_x4(b"\x00\x22"), Ok(22));
        assert_eq!(decode_bcd_x4(b"\x00\x23"), Ok(23));
        assert_eq!(decode_bcd_x4(b"\x00\x24"), Ok(24));
        assert_eq!(decode_bcd_x4(b"\x00\x25"), Ok(25));
        assert_eq!(decode_bcd_x4(b"\x00\x26"), Ok(26));
        assert_eq!(decode_bcd_x4(b"\x00\x27"), Ok(27));
        assert_eq!(decode_bcd_x4(b"\x00\x28"), Ok(28));
        assert_eq!(decode_bcd_x4(b"\x00\x29"), Ok(29));
        assert_eq!(decode_bcd_x4(b"\x00\x30"), Ok(30));
        assert_eq!(decode_bcd_x4(b"\x00\x32"), Ok(32));
        assert_eq!(decode_bcd_x4(b"\x00\x43"), Ok(43));
        assert_eq!(decode_bcd_x4(b"\x00\x54"), Ok(54));
        assert_eq!(decode_bcd_x4(b"\x00\x65"), Ok(65));
        assert_eq!(decode_bcd_x4(b"\x00\x76"), Ok(76));
        assert_eq!(decode_bcd_x4(b"\x00\x87"), Ok(87));
        assert_eq!(decode_bcd_x4(b"\x00\x99"), Ok(99));
        assert_eq!(decode_bcd_x4(b"\x01\x05"), Ok(105));
        assert_eq!(decode_bcd_x4(b"\x01\x37"), Ok(137));
        assert_eq!(decode_bcd_x4(b"\x02\x93"), Ok(293));
        assert_eq!(decode_bcd_x4(b"\x03\x60"), Ok(360));
        assert_eq!(decode_bcd_x4(b"\x12\x34"), Ok(1234));
        assert_eq!(decode_bcd_x4(b"\x56\x78"), Ok(5678));
        assert_eq!(decode_bcd_x4(b"\x99\x99"), Ok(9999));
    }

    #[test]
    fn test_encode_bcd_x2() {
        assert_eq!(encode_bcd_x2(0), Ok(0x0));
        assert_eq!(encode_bcd_x2(1), Ok(0x1));
        assert_eq!(encode_bcd_x2(9), Ok(0x9));
        assert_eq!(encode_bcd_x2(10), Ok(0x10));
        assert_eq!(encode_bcd_x2(19), Ok(0x19));
        assert_eq!(encode_bcd_x2(99), Ok(0x99));

        assert!(encode_bcd_x2(100).is_err());
    }

    #[test]
    fn test_encode_bcd_x4() {
        assert_eq!(encode_bcd_x4(0), Ok([0x0, 0x0]));
        assert_eq!(encode_bcd_x4(1), Ok([0x0, 0x1]));
        assert_eq!(encode_bcd_x4(9), Ok([0x0, 0x9]));
        assert_eq!(encode_bcd_x4(10), Ok([0x0, 0x10]));
        assert_eq!(encode_bcd_x4(19), Ok([0x0, 0x19]));
        assert_eq!(encode_bcd_x4(100), Ok([0x1, 0x00]));
        assert_eq!(encode_bcd_x4(101), Ok([0x1, 0x01]));
        assert_eq!(encode_bcd_x4(119), Ok([0x1, 0x19]));
        assert_eq!(encode_bcd_x4(1000), Ok([0x10, 0x0]));
        assert_eq!(encode_bcd_x4(1019), Ok([0x10, 0x19]));
        assert_eq!(encode_bcd_x4(9999), Ok([0x99, 0x99]));

        assert!(encode_bcd_x4(10000).is_err());
    }

    #[test]
    fn encode_tag_regular_09() {
        let mut buf = BytesMut::new();
        Tag::Regular(9).encode_to_buf(&mut buf).unwrap();
        assert_eq!(buf, b"T\x00\x09\x00"[..]);
    }

    #[test]
    fn encode_tag_regular_19() {
        let mut buf = BytesMut::new();
        Tag::Regular(19).encode_to_buf(&mut buf).unwrap();
        assert_eq!(buf, b"T\x00\x19\x00"[..]);
    }

    #[test]
    fn encode_tag_iso_19() {
        let mut buf = BytesMut::new();
        Tag::Iso(19).encode_to_buf(&mut buf).unwrap();
        assert_eq!(buf, b"I\x00\x19\x00"[..]);
    }

    #[test]
    fn encode_tag_iso_191() {
        let mut buf = BytesMut::new();
        Tag::Iso(191).encode_to_buf(&mut buf).unwrap();
        assert_eq!(buf, b"I\x01\x91\x00"[..]);
    }

    #[test]
    fn encode_tag_subfield_19_2() {
        let mut buf = BytesMut::new();
        Tag::IsoSubfield(19, 2).encode_to_buf(&mut buf).unwrap();
        assert_eq!(buf, b"S\x00\x19\x02"[..]);
    }

    #[test]
    fn encode_tag_subfield_19_22() {
        let mut buf = BytesMut::new();
        Tag::IsoSubfield(19, 22).encode_to_buf(&mut buf).unwrap();
        assert_eq!(buf, b"S\x00\x19\x22"[..]);
    }

    #[test]
    fn encode_field() {
        let mut buf = BytesMut::new();
        encode_field_to_buf(Tag::Regular(9), "IDDQD".as_bytes(), &mut buf).unwrap();
        assert_eq!(buf, b"T\x00\x09\x00\x00\x05IDDQD"[..]);
    }

    #[test]
    fn encode_field_zero() {
        let mut buf = BytesMut::new();
        encode_field_to_buf(Tag::Iso(9), "".as_bytes(), &mut buf).unwrap();
        assert_eq!(buf, b"I\x00\x09\x00\x00\x00"[..]);
    }

    #[test]
    fn decode_field() {
        let mut buf = Bytes::from_static(b"T\x00\x09\x00\x00\x05IDDQD");
        let (tag, data) = decode_field_from_cursor(&mut buf).unwrap();
        assert_eq!(tag, Tag::Regular(9));
        assert_eq!(data[..], b"IDDQD"[..]);
    }

    #[test]
    fn decode_field_zero() {
        let mut buf = Bytes::from_static(b"I\x00\x09\x00\x00\x00");
        let (tag, data) = decode_field_from_cursor(&mut buf).unwrap();
        assert_eq!(tag, Tag::Iso(9));
        assert_eq!(data[..], b""[..]);
    }
}
