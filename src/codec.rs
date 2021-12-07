use bytes::{BufMut, BytesMut};
use tokio_util::codec::{Decoder, Encoder};

use crate::{SigmaRequest, SigmaResponse};

/// Errors of [`tokio_util::codec::Framed`] stream with [`SigmaClientProtocol`] codec.
#[derive(Debug, thiserror::Error)]
pub enum ClientProtocolError {
    #[error(transparent)]
    ExtfgSigma(#[from] crate::Error),
    #[error(transparent)]
    WrongLenUtf8(#[from] std::str::Utf8Error),
    #[error(transparent)]
    WrongLenInt(#[from] std::num::ParseIntError),
    #[error(transparent)]
    StdIoError(#[from] std::io::Error),
}

impl PartialEq for ClientProtocolError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::StdIoError(self_io), Self::StdIoError(other_io)) => {
                format!("{:#}", self_io) == format!("{:#}", other_io)
            }
            (Self::ExtfgSigma(x), Self::ExtfgSigma(y)) => x == y,
            (Self::WrongLenUtf8(x), Self::WrongLenUtf8(y)) => x == y,
            (Self::WrongLenInt(x), Self::WrongLenInt(y)) => x == y,
            (_, _) => false,
        }
    }
}

pub const LENGTH_BYTES_COUNT: usize = 5;

/// Codec for semi-automated encoding/decoding of [`SigmaRequest`]s and [`SigmaResponse`]s.
pub struct SigmaClientProtocol;

impl Decoder for SigmaClientProtocol {
    type Item = SigmaResponse;
    type Error = ClientProtocolError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let current_length = src.len();

        if current_length < LENGTH_BYTES_COUNT {
            src.reserve(LENGTH_BYTES_COUNT - current_length);
            return Ok(None);
        }

        let msg_len = std::str::from_utf8(&src[0..LENGTH_BYTES_COUNT])
            .map_err(ClientProtocolError::from)?
            .parse::<usize>()
            .map_err(ClientProtocolError::from)?;

        let overall_length = msg_len + LENGTH_BYTES_COUNT;

        Ok(match current_length < overall_length {
            true => {
                src.reserve(overall_length - current_length);
                None
            }
            false => Some(SigmaResponse::decode(src.split_to(overall_length).into())?),
        })
    }
}

impl Encoder<SigmaRequest> for SigmaClientProtocol {
    type Error = ClientProtocolError;

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

        assert!(matches!(SigmaClientProtocol.decode(&mut buf), Ok(None)));
        assert_eq!(buf, DATA);
    }

    #[test]
    fn decode_incomplete_length() {
        const DATA: &[u8] = b"0002";
        let mut buf = BytesMut::new();
        buf.put(DATA);

        assert!(matches!(SigmaClientProtocol.decode(&mut buf), Ok(None)));
        assert_eq!(buf, DATA);
    }

    #[test]
    fn decode_complete_length() {
        const DATA: &[u8] = b"00024";
        let mut buf = BytesMut::new();
        buf.put(DATA);

        assert!(matches!(SigmaClientProtocol.decode(&mut buf), Ok(None)));
        assert_eq!(buf, DATA);
    }

    #[test]
    fn decode_incomplete_data() {
        const DATA: &[u8] = b"0002401104007040978T\x00\x31\x00\x00\x0484";
        let mut buf = BytesMut::new();
        buf.put(DATA);

        assert!(matches!(SigmaClientProtocol.decode(&mut buf), Ok(None)));
        assert_eq!(buf, DATA);
    }

    #[test]
    fn decode_complete_data() {
        const DATA: &[u8] = b"0002401104007040978T\x00\x31\x00\x00\x048495";
        let mut buf = BytesMut::new();
        buf.put(DATA);

        assert!(matches!(SigmaClientProtocol.decode(&mut buf), Ok(Some(_))));
        assert_eq!(buf, b""[..]);
    }
}
