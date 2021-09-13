use crate::ikev2::IkeV2Header;
use crate::ikev2_parser::parse_ikev2_header;
use nom::bytes::streaming::take;
use nom::combinator::rest;
use nom::number::streaming::be_u32;
use nom::IResult;

/// Encapsulating Security Payload Packet Format
///
/// Defined in [RFC2406](https://tools.ietf.org/html/rfc2406) section 2
#[derive(Debug)]
pub struct ESPHeader<'a> {
    pub spi_index: &'a [u8],
    pub seq: u32,
    pub data: &'a [u8],
}

/// UDP-encapsulated Packet Formats
///
/// Defined in [RFC3948](https://tools.ietf.org/html/rfc3948) section 2
#[derive(Debug)]
pub enum ESPData<'a> {
    ESP(ESPHeader<'a>),
    IKE(IkeV2Header),
}

/// Parse an encapsulated ESP packet
///
/// The type of encapsulated data depends on the first field (`spi_index`): 0 is a forbidden SPI
/// index, and indicates that the header is an IKE header.
/// Any other value indicates an ESP header.
///
/// *Note: input is entirely consumed*
pub fn parse_esp_encapsulated(i: &[u8]) -> IResult<&[u8], ESPData> {
    if be_u32(i)?.1 == 0 {
        parse_ikev2_header(i).map(|x| (x.0, ESPData::IKE(x.1)))
    } else {
        parse_esp_header(i).map(|x| (x.0, ESPData::ESP(x.1)))
    }
}

/// Parse an ESP packet
///
/// The ESP header contains:
///
/// - the SPI index
/// - the sequence number
/// - the payload data (which can be encrypted)
///
/// *Note: input is entirely consumed*
pub fn parse_esp_header(i: &[u8]) -> IResult<&[u8], ESPHeader> {
    let (i, spi_index) = take(4usize)(i)?;
    let (i, seq) = be_u32(i)?;
    let (i, data) = rest(i)?;
    let hdr = ESPHeader {
        spi_index,
        seq,
        data,
    };
    Ok((i, hdr))
}
