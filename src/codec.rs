use bytes::{BufMut, BytesMut};
use tokio_util::codec::{Decoder, Encoder};

use crate::{SigmaRequest, SigmaResponse};

/// Ошибка [`Framed`] транспорта с [`SigmaProtocol`].
#[derive(Debug, thiserror::Error)]
pub enum ProtocolError {
    #[error(transparent)]
    ExtfgSigma(#[from] crate::Error),
    #[error(transparent)]
    WrongLenUtf8(#[from] std::str::Utf8Error),
    #[error(transparent)]
    WrongLenInt(#[from] std::num::ParseIntError),
    #[error(transparent)]
    StdIoError(#[from] std::io::Error),
}

impl PartialEq for ProtocolError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::StdIoError(self_io), Self::StdIoError(other_io)) => {
                format!("{:#}", self_io) == format!("{:#}", other_io)
            }
            (this, that) => this == that,
        }
    }
}

pub struct SigmaProtocol;

impl Decoder for SigmaProtocol {
    type Item = SigmaResponse;
    type Error = ProtocolError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        const LEN_BYTES_COUNT: usize = 5;

        if src.len() < LEN_BYTES_COUNT {
            return Ok(None);
        }

        let msg_len = std::str::from_utf8(&src[0..LEN_BYTES_COUNT])
            .map_err(ProtocolError::from)?
            .parse::<usize>()
            .map_err(ProtocolError::from)?;

        let overall_length = msg_len + LEN_BYTES_COUNT;

        Ok(match src.len() < overall_length {
            true => None,
            false => Some(SigmaResponse::decode(src.split_to(overall_length).into())?),
        })
    }
}

impl Encoder<SigmaRequest> for SigmaProtocol {
    type Error = ProtocolError;

    fn encode(&mut self, item: SigmaRequest, dst: &mut BytesMut) -> Result<(), Self::Error> {
        dst.put(item.encode()?);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_zero() {
        const DATA: &[u8] = b"";
        let mut buf = BytesMut::new();
        buf.put(DATA);

        assert!(matches!(SigmaProtocol.decode(&mut buf), Ok(None)));
        assert_eq!(buf, DATA);
    }

    #[test]
    fn decode_incomplete_length() {
        const DATA: &[u8] = b"0002";
        let mut buf = BytesMut::new();
        buf.put(DATA);

        assert!(matches!(SigmaProtocol.decode(&mut buf), Ok(None)));
        assert_eq!(buf, DATA);
    }

    #[test]
    fn decode_complete_length() {
        const DATA: &[u8] = b"00024";
        let mut buf = BytesMut::new();
        buf.put(DATA);

        assert!(matches!(SigmaProtocol.decode(&mut buf), Ok(None)));
        assert_eq!(buf, DATA);
    }

    #[test]
    fn decode_incomplete_data() {
        const DATA: &[u8] = b"0002401104007040978T\x00\x31\x00\x00\x0484";
        let mut buf = BytesMut::new();
        buf.put(DATA);

        assert!(matches!(SigmaProtocol.decode(&mut buf), Ok(None)));
        assert_eq!(buf, DATA);
    }

    #[test]
    fn decode_complete_data() {
        const DATA: &[u8] = b"0002401104007040978T\x00\x31\x00\x00\x048495";
        let mut buf = BytesMut::new();
        buf.put(DATA);

        assert!(matches!(SigmaProtocol.decode(&mut buf), Ok(Some(_))));
        assert_eq!(buf, b""[..]);
    }
}
