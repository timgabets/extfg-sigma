extern crate rand;

use bytes::{BufMut, BytesMut};
use rand::Rng;
use std::convert::TryInto;

/// Generate Authorization Serno
pub fn gen_auth_serno() -> u64 {
    let mut rng = rand::thread_rng();
    let rrn: u64 = rng.gen();
    rrn
}

fn pop(x: &[u8]) -> &[u8; 2] {
    x.try_into().expect("slice with incorrect length")
}

#[rustfmt::skip]
pub fn bcd2u16(x: &[u8]) -> u16 {
    let bcd_table = [
         0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 0, 0, 0, 0, 0, 0,
        10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 0, 0, 0, 0, 0, 0,
        20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 0, 0, 0, 0, 0, 0,
        30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 0, 0, 0, 0, 0, 0,
        40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 0, 0, 0, 0, 0, 0,
        50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 0, 0, 0, 0, 0, 0,
        60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 0, 0, 0, 0, 0, 0,
        70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 0, 0, 0, 0, 0, 0,
        80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 0, 0, 0, 0, 0, 0,
        90, 91, 92, 93, 94, 95, 96, 97, 98, 99
    ];
    let index: usize = u16::from_be_bytes(*pop(&x[0..2])) as usize;
    if index < bcd_table.len() {
        /* Values less than 0x99 */
        return bcd_table[index];
    } else if index >= 0x100 {
        /* TODO: Values largen than than 0x100 */
    }
    0
}

#[rustfmt::skip]
fn dec2bcd(dec: usize) -> i32 {
    // As for now (July 2020) there is no stable BCD library in Rust, and I would not like to implement the one.
    // Convertion table is quite enough for now.
    let bcd_table = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39,
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49,
        0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59,
        0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69,
        0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79,
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89,
        0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99,
        0x100, 0x101, 0x102, 0x103, 0x104, 0x105, 0x106, 0x107, 0x108, 0x109,
        0x110, 0x111, 0x112, 0x113, 0x114, 0x115, 0x116, 0x117, 0x118, 0x119,
        0x120, 0x121, 0x122, 0x123, 0x124, 0x125, 0x126, 0x127, 0x128,
    ];
    if dec < bcd_table.len() {
        return bcd_table[dec];
    }
    -1
}

pub fn msg_len(len: usize) -> BytesMut {
    let mut buf = BytesMut::with_capacity(64);
    buf.put_u8(((len % 100000) / 10000) as u8 + 0x30);
    buf.put_u8(((len % 10000) / 1000) as u8 + 0x30);
    buf.put_u8(((len % 1000) / 100) as u8 + 0x30);
    buf.put_u8(((len % 100) / 10) as u8 + 0x30);
    buf.put_u8((len % 10) as u8 + 0x30);

    buf.split()
}

pub enum TagType {
    Regular,
    Iso,
}

pub fn serialize_tag(t: TagType, index: usize, data: &str) -> BytesMut {
    // TODO: what the hell is capacity 🤔?
    let mut buf = BytesMut::with_capacity(64);
    match t {
        TagType::Regular => buf.put(&b"T"[..]),
        TagType::Iso => buf.put(&b"I"[..]),
    };
    buf.put_u16(dec2bcd(index) as u16);
    buf.put_u8(0);
    buf.put_u16(dec2bcd(data.len()) as u16);
    buf.put(data.as_bytes());

    buf.split()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bcd2u16() {
        assert_eq!(bcd2u16(b"\x00\x01"), 1);
        assert_eq!(bcd2u16(b"\x00\x02"), 2);
        assert_eq!(bcd2u16(b"\x00\x03"), 3);
        assert_eq!(bcd2u16(b"\x00\x04"), 4);
        assert_eq!(bcd2u16(b"\x00\x05"), 5);
        assert_eq!(bcd2u16(b"\x00\x06"), 6);
        assert_eq!(bcd2u16(b"\x00\x07"), 7);
        assert_eq!(bcd2u16(b"\x00\x08"), 8);
        assert_eq!(bcd2u16(b"\x00\x09"), 9);
        assert_eq!(bcd2u16(b"\x00\x10"), 10);
        assert_eq!(bcd2u16(b"\x00\x11"), 11);
        assert_eq!(bcd2u16(b"\x00\x12"), 12);
        assert_eq!(bcd2u16(b"\x00\x13"), 13);
        assert_eq!(bcd2u16(b"\x00\x14"), 14);
        assert_eq!(bcd2u16(b"\x00\x15"), 15);
        assert_eq!(bcd2u16(b"\x00\x16"), 16);
        assert_eq!(bcd2u16(b"\x00\x17"), 17);
        assert_eq!(bcd2u16(b"\x00\x18"), 18);
        assert_eq!(bcd2u16(b"\x00\x19"), 19);
        assert_eq!(bcd2u16(b"\x00\x20"), 20);
        assert_eq!(bcd2u16(b"\x00\x21"), 21);
        assert_eq!(bcd2u16(b"\x00\x22"), 22);
        assert_eq!(bcd2u16(b"\x00\x23"), 23);
        assert_eq!(bcd2u16(b"\x00\x24"), 24);
        assert_eq!(bcd2u16(b"\x00\x25"), 25);
        assert_eq!(bcd2u16(b"\x00\x26"), 26);
        assert_eq!(bcd2u16(b"\x00\x27"), 27);
        assert_eq!(bcd2u16(b"\x00\x28"), 28);
        assert_eq!(bcd2u16(b"\x00\x29"), 29);
        assert_eq!(bcd2u16(b"\x00\x30"), 30);
        assert_eq!(bcd2u16(b"\x00\x32"), 32);
        assert_eq!(bcd2u16(b"\x00\x43"), 43);
        assert_eq!(bcd2u16(b"\x00\x54"), 54);
        assert_eq!(bcd2u16(b"\x00\x65"), 65);
        assert_eq!(bcd2u16(b"\x00\x76"), 76);
        assert_eq!(bcd2u16(b"\x00\x87"), 87);
        assert_eq!(bcd2u16(b"\x00\x99"), 99);
        assert_eq!(
            bcd2u16(b"\x01\x00"),
            0,
            "Values larger than 0x100 are not yet implemented"
        );
    }

    #[test]
    fn test_dec2bcd() {
        assert_eq!(dec2bcd(0), 0x0);
        assert_eq!(dec2bcd(1), 0x1);
        assert_eq!(dec2bcd(11), 0x11);
        assert_eq!(dec2bcd(22), 0x22);
        assert_eq!(dec2bcd(33), 0x33);
        assert_eq!(dec2bcd(37), 0x37);
        assert_eq!(dec2bcd(44), 0x44);
        assert_eq!(dec2bcd(55), 0x55);
        assert_eq!(dec2bcd(69), 0x69);
        assert_eq!(dec2bcd(99), 0x99);
        assert_eq!(dec2bcd(100), 0x100);
        assert_eq!(dec2bcd(102), 0x0102);
        assert_eq!(dec2bcd(128), 0x0128);
        assert_eq!(dec2bcd(129), -1, "BCD 129 is not implemented");
    }

    #[test]
    fn t0009() {
        let serialized = serialize_tag(TagType::Regular, 9, "IDDQD");
        assert_eq!(serialized, b"T\x00\x09\x00\x00\x05IDDQD"[..]);
    }

    #[test]
    fn t0022() {
        let serialized = serialize_tag(TagType::Regular, 22, "XYZ");
        assert_eq!(serialized, b"T\x00\x22\x00\x00\x03XYZ"[..]);
    }

    #[test]
    fn t0088() {
        let serialized = serialize_tag(TagType::Regular, 88, "Lorem ipsum dolor sit amet");
        assert_eq!(
            serialized,
            b"T\x00\x88\x00\x00\x26Lorem ipsum dolor sit amet"[..]
        );
    }
    #[test]
    fn t0103() {
        let serialized = serialize_tag(TagType::Regular, 103, "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua");
        assert_eq!(
                serialized,
                b"T\x01\x03\x00\x01\x22Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua"[..]
            );
    }
    #[test]
    fn i0037() {
        let serialized = serialize_tag(TagType::Iso, 37, "716387162837618273");
        assert_eq!(serialized, b"I\x00\x37\x00\x00\x18716387162837618273"[..]);
    }

    #[test]
    fn test_msg_len() {
        assert_eq!(msg_len(1), b"00001"[..]);
        assert_eq!(msg_len(2), b"00002"[..]);
        assert_eq!(msg_len(9), b"00009"[..]);
        assert_eq!(msg_len(25), b"00025"[..]);
        assert_eq!(msg_len(68), b"00068"[..]);
        assert_eq!(msg_len(99), b"00099"[..]);
        assert_eq!(msg_len(101), b"00101"[..]);
        assert_eq!(msg_len(123), b"00123"[..]);
        assert_eq!(msg_len(255), b"00255"[..]);
        assert_eq!(msg_len(256), b"00256"[..]);
        assert_eq!(msg_len(678), b"00678"[..]);
        assert_eq!(msg_len(987), b"00987"[..]);
        assert_eq!(msg_len(1024), b"01024"[..]);
        assert_eq!(msg_len(2048), b"02048"[..]);
        assert_eq!(msg_len(4096), b"04096"[..]);
        assert_eq!(msg_len(9876), b"09876"[..]);
        assert_eq!(msg_len(10240), b"10240"[..]);
        assert_eq!(msg_len(98765), b"98765"[..]);
    }
}
