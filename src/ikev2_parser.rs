use crate::error::IPsecError;
use crate::ikev2::*;
use crate::ikev2_notify::NotifyType;
use crate::ikev2_transforms::*;
use nom::bytes::streaming::take;
use nom::combinator::{complete, cond, map, map_parser, verify};
use nom::error::{make_error, ErrorKind};
use nom::multi::{count, many1};
use nom::number::streaming::{be_u16, be_u32, be_u64, be_u8};
use nom::{Err, IResult, Needed};

pub fn parse_ikev2_header(i: &[u8]) -> IResult<&[u8], IkeV2Header> {
    if i.len() < 28 {
        return Err(Err::Incomplete(Needed::new(28)));
    }
    let (i, init_spi) = be_u64(i)?;
    let (i, resp_spi) = be_u64(i)?;
    let (i, next_payload) = map(be_u8, IkePayloadType)(i)?;
    let (i, vers) = be_u8(i)?;
    let maj_ver = vers >> 4;
    let min_ver = vers & 0b1111;
    let (i, exch_type) = map(be_u8, IkeExchangeType)(i)?;
    let (i, flags) = be_u8(i)?;
    let (i, msg_id) = be_u32(i)?;
    let (i, length) = be_u32(i)?;
    let hdr = IkeV2Header {
        init_spi,
        resp_spi,
        next_payload,
        maj_ver,
        min_ver,
        exch_type,
        flags,
        msg_id,
        length,
    };
    Ok((i, hdr))
}

#[inline]
fn bits_split_1(i: &[u8]) -> IResult<&[u8], (u8, u8)> {
    let (i, b) = be_u8(i)?;
    let b1 = b >> 7;
    let b2_7 = b & 0b_0111_1111;
    Ok((i, (b1, b2_7)))
}

pub fn parse_ikev2_payload_generic(i: &[u8]) -> IResult<&[u8], IkeV2GenericPayload> {
    let (i, next_payload_type) = map(be_u8, IkePayloadType)(i)?;
    let (i, b) = bits_split_1(i)?;
    let (i, payload_length) = verify(be_u16, |&n| n >= 4)(i)?;
    let (i, payload) = take(payload_length - 4)(i)?;
    let hdr = IkeV2PayloadHeader {
        next_payload_type,
        critical: b.0 == 1,
        reserved: b.1,
        payload_length,
    };
    let payload = IkeV2GenericPayload { hdr, payload };
    Ok((i, payload))
}

pub fn parse_ikev2_transform(i: &[u8]) -> IResult<&[u8], IkeV2RawTransform> {
    let (i, last) = be_u8(i)?;
    let (i, reserved1) = be_u8(i)?;
    let (i, transform_length) = be_u16(i)?;
    let (i, transform_type) = be_u8(i)?;
    let (i, reserved2) = be_u8(i)?;
    let (i, transform_id) = be_u16(i)?;
    // we have to specify a callback here to force lazy evaluation,
    // because the function arguments are evaluated *before* the test (causing underflow)
    let (i, attributes) = cond(transform_length > 8, |d| take(transform_length - 8)(d))(i)?;
    let transform = IkeV2RawTransform {
        last,
        reserved1,
        transform_length,
        transform_type: IkeTransformType(transform_type),
        reserved2,
        transform_id,
        attributes,
    };
    Ok((i, transform))
}

pub fn parse_ikev2_proposal(i: &[u8]) -> IResult<&[u8], IkeV2Proposal> {
    if i.len() < 8 {
        return Err(Err::Incomplete(Needed::new(8)));
    }
    let (i, last) = be_u8(i)?;
    let (i, reserved) = be_u8(i)?;
    let (i, proposal_length) = be_u16(i)?;
    let (i, proposal_num) = be_u8(i)?;
    let (i, protocol_id) = map(be_u8, ProtocolID)(i)?;
    let (i, spi_size) = be_u8(i)?;
    let (i, num_transforms) = be_u8(i)?;
    let (i, spi) = cond(spi_size > 0, take(spi_size))(i)?;
    if proposal_length < (8u16 + spi_size as u16) {
        return Err(Err::Error(make_error(i, ErrorKind::Verify)));
    }
    let (i, transforms) = map_parser(
        take(proposal_length - 8 - (spi_size as u16)),
        count(parse_ikev2_transform, num_transforms as usize),
    )(i)?;
    let proposal = IkeV2Proposal {
        last,
        reserved,
        proposal_length,
        proposal_num,
        protocol_id,
        spi_size,
        num_transforms,
        spi,
        transforms,
    };
    Ok((i, proposal))
}

pub fn parse_ikev2_payload_sa(i: &[u8], _length: u16) -> IResult<&[u8], IkeV2PayloadContent> {
    map(
        many1(complete(parse_ikev2_proposal)),
        IkeV2PayloadContent::SA,
    )(i)
}

pub fn parse_ikev2_payload_kex(i: &[u8], length: u16) -> IResult<&[u8], IkeV2PayloadContent> {
    if length < 4 {
        return Err(Err::Error(make_error(i, ErrorKind::Verify)));
    }
    let (i, dh_group) = map(be_u16, IkeTransformDHType)(i)?;
    let (i, reserved) = be_u16(i)?;
    let (i, kex_data) = take(length - 4)(i)?;
    let payload = KeyExchangePayload {
        dh_group,
        reserved,
        kex_data,
    };
    Ok((i, IkeV2PayloadContent::KE(payload)))
}

pub fn parse_ikev2_payload_ident_init(
    i: &[u8],
    length: u16,
) -> IResult<&[u8], IkeV2PayloadContent> {
    if length < 4 {
        return Err(Err::Error(make_error(i, ErrorKind::Verify)));
    }
    let (i, id_type) = map(be_u8, IdentificationType)(i)?;
    let (i, reserved1) = be_u8(i)?;
    let (i, reserved2) = be_u16(i)?;
    let (i, ident_data) = take(length - 4)(i)?;
    let payload = IdentificationPayload {
        id_type,
        reserved1,
        reserved2,
        ident_data,
    };
    Ok((i, IkeV2PayloadContent::IDi(payload)))
}

pub fn parse_ikev2_payload_ident_resp(
    i: &[u8],
    length: u16,
) -> IResult<&[u8], IkeV2PayloadContent> {
    if length < 4 {
        return Err(Err::Error(make_error(i, ErrorKind::Verify)));
    }
    let (i, id_type) = map(be_u8, IdentificationType)(i)?;
    let (i, reserved1) = be_u8(i)?;
    let (i, reserved2) = be_u16(i)?;
    let (i, ident_data) = take(length - 4)(i)?;
    let payload = IdentificationPayload {
        id_type,
        reserved1,
        reserved2,
        ident_data,
    };
    Ok((i, IkeV2PayloadContent::IDr(payload)))
}

pub fn parse_ikev2_payload_certificate(
    i: &[u8],
    length: u16,
) -> IResult<&[u8], IkeV2PayloadContent> {
    if length < 1 {
        return Err(Err::Error(make_error(i, ErrorKind::Verify)));
    }
    let (i, cert_encoding) = map(be_u8, CertificateEncoding)(i)?;
    let (i, cert_data) = take(length - 1)(i)?;
    let payload = CertificatePayload {
        cert_encoding,
        cert_data,
    };
    Ok((i, IkeV2PayloadContent::Certificate(payload)))
}

pub fn parse_ikev2_payload_certificate_request(
    i: &[u8],
    length: u16,
) -> IResult<&[u8], IkeV2PayloadContent> {
    if length < 1 {
        return Err(Err::Error(make_error(i, ErrorKind::Verify)));
    }
    let (i, cert_encoding) = map(be_u8, CertificateEncoding)(i)?;
    let (i, ca_data) = take(length - 1)(i)?;
    let payload = CertificateRequestPayload {
        cert_encoding,
        ca_data,
    };
    Ok((i, IkeV2PayloadContent::CertificateRequest(payload)))
}

pub fn parse_ikev2_payload_authentication(
    i: &[u8],
    length: u16,
) -> IResult<&[u8], IkeV2PayloadContent> {
    if length < 4 {
        return Err(Err::Error(make_error(i, ErrorKind::Verify)));
    }
    let (i, auth_method) = map(be_u8, AuthenticationMethod)(i)?;
    let (i, auth_data) = take(length - 4)(i)?;
    let payload = AuthenticationPayload {
        auth_method,
        auth_data,
    };
    Ok((i, IkeV2PayloadContent::Authentication(payload)))
}

pub fn parse_ikev2_payload_nonce(i: &[u8], length: u16) -> IResult<&[u8], IkeV2PayloadContent> {
    let (i, nonce_data) = take(length)(i)?;
    Ok((i, IkeV2PayloadContent::Nonce(NoncePayload { nonce_data })))
}

pub fn parse_ikev2_payload_notify(i: &[u8], length: u16) -> IResult<&[u8], IkeV2PayloadContent> {
    let (i, protocol_id) = map(be_u8, ProtocolID)(i)?;
    let (i, spi_size) = be_u8(i)?;
    let (i, notify_type) = map(be_u16, NotifyType)(i)?;
    let (i, spi) = cond(spi_size > 0, take(spi_size))(i)?;
    let (i, notify_data) = cond(
        length > 8 + spi_size as u16,
        // we have to specify a callback here to force lazy evaluation,
        // because the function arguments are evaluated *before* the test (causing underflow)
        |d| take(length - (8 + spi_size as u16))(d),
    )(i)?;
    let payload = NotifyPayload {
        protocol_id,
        spi_size,
        notify_type,
        spi,
        notify_data,
    };
    Ok((i, IkeV2PayloadContent::Notify(payload)))
}

pub fn parse_ikev2_payload_vendor_id(i: &[u8], length: u16) -> IResult<&[u8], IkeV2PayloadContent> {
    if length < 8 {
        return Err(Err::Error(make_error(i, ErrorKind::Verify)));
    }
    let (i, vendor_id) = take(length - 8)(i)?;
    Ok((
        i,
        IkeV2PayloadContent::VendorID(VendorIDPayload { vendor_id }),
    ))
}

pub fn parse_ikev2_payload_delete(i: &[u8], length: u16) -> IResult<&[u8], IkeV2PayloadContent> {
    if length < 8 {
        return Err(Err::Error(make_error(i, ErrorKind::Verify)));
    }
    let (i, protocol_id) = map(be_u8, ProtocolID)(i)?;
    let (i, spi_size) = be_u8(i)?;
    let (i, num_spi) = be_u16(i)?;
    let (i, spi) = take(length - 8)(i)?;
    let payload = DeletePayload {
        protocol_id,
        spi_size,
        num_spi,
        spi,
    };
    Ok((i, IkeV2PayloadContent::Delete(payload)))
}

fn parse_ts_addr(i: &[u8], t: TSType) -> IResult<&[u8], &[u8]> {
    match t {
        TSType::IPv4AddrRange => take(4usize)(i),
        TSType::IPv6AddrRange => take(16usize)(i),
        _ => Err(nom::Err::Error(make_error(i, ErrorKind::Switch))),
    }
}

fn parse_ikev2_ts(i: &[u8]) -> IResult<&[u8], TrafficSelector> {
    let (i, ts_type) = map(be_u8, TSType)(i)?;
    let (i, ip_proto_id) = be_u8(i)?;
    let (i, sel_length) = be_u16(i)?;
    let (i, start_port) = be_u16(i)?;
    let (i, end_port) = be_u16(i)?;
    let (i, start_addr) = parse_ts_addr(i, ts_type)?;
    let (i, end_addr) = parse_ts_addr(i, ts_type)?;
    let ts = TrafficSelector {
        ts_type,
        ip_proto_id,
        sel_length,
        start_port,
        end_port,
        start_addr,
        end_addr,
    };
    Ok((i, ts))
}

pub fn parse_ikev2_payload_ts(i: &[u8], length: u16) -> IResult<&[u8], TrafficSelectorPayload> {
    if length < 4 {
        return Err(Err::Error(make_error(i, ErrorKind::Verify)));
    }
    let (i, num_ts) = be_u8(i)?;
    let (i, reserved) = take(3usize)(i)?;
    let (i, ts) = map_parser(take(length - 4), many1(complete(parse_ikev2_ts)))(i)?;
    let payload = TrafficSelectorPayload {
        num_ts,
        reserved,
        ts,
    };
    Ok((i, payload))
}

pub fn parse_ikev2_payload_ts_init(i: &[u8], length: u16) -> IResult<&[u8], IkeV2PayloadContent> {
    map(
        |d| parse_ikev2_payload_ts(d, length),
        IkeV2PayloadContent::TSi,
    )(i)
}

pub fn parse_ikev2_payload_ts_resp(i: &[u8], length: u16) -> IResult<&[u8], IkeV2PayloadContent> {
    map(
        |d| parse_ikev2_payload_ts(d, length),
        IkeV2PayloadContent::TSr,
    )(i)
}

pub fn parse_ikev2_payload_encrypted(i: &[u8], length: u16) -> IResult<&[u8], IkeV2PayloadContent> {
    map(take(length), |d| {
        IkeV2PayloadContent::Encrypted(EncryptedPayload(d))
    })(i)
}

pub fn parse_ikev2_payload_unknown(i: &[u8], length: u16) -> IResult<&[u8], IkeV2PayloadContent> {
    map(take(length), IkeV2PayloadContent::Unknown)(i)
}

#[rustfmt::skip]
pub fn parse_ikev2_payload_with_type(
    i: &[u8],
    length: u16,
    next_payload_type: IkePayloadType,
) -> IResult<&[u8], IkeV2PayloadContent> {
    let f = match next_payload_type {
        // IkePayloadType::NoNextPayload       => parse_ikev2_payload_unknown, // XXX ?
        IkePayloadType::SecurityAssociation       => parse_ikev2_payload_sa,
        IkePayloadType::KeyExchange               => parse_ikev2_payload_kex,
        IkePayloadType::IdentInitiator            => parse_ikev2_payload_ident_init,
        IkePayloadType::IdentResponder            => parse_ikev2_payload_ident_resp,
        IkePayloadType::Certificate               => parse_ikev2_payload_certificate,
        IkePayloadType::CertificateRequest        => parse_ikev2_payload_certificate_request,
        IkePayloadType::Authentication            => parse_ikev2_payload_authentication,
        IkePayloadType::Nonce                     => parse_ikev2_payload_nonce,
        IkePayloadType::Notify                    => parse_ikev2_payload_notify,
        IkePayloadType::Delete                    => parse_ikev2_payload_delete,
        IkePayloadType::VendorID                  => parse_ikev2_payload_vendor_id,
        IkePayloadType::TrafficSelectorInitiator  => parse_ikev2_payload_ts_init,
        IkePayloadType::TrafficSelectorResponder  => parse_ikev2_payload_ts_resp,
        IkePayloadType::EncryptedAndAuthenticated => parse_ikev2_payload_encrypted,
        // None                                               => parse_ikev2_payload_unknown,
        _ => parse_ikev2_payload_unknown,
        // _ => panic!("unknown type {}",next_payload_type),
    };
    map_parser(take(length),move |d| f(d, length))(i)
}

fn parse_ikev2_payload_list_fold<'a>(
    res_v: Result<Vec<IkeV2Payload<'a>>, IPsecError>,
    p: IkeV2GenericPayload<'a>,
) -> Result<Vec<IkeV2Payload<'a>>, IPsecError> {
    let mut v = res_v?;
    // println!("parse_payload_list_fold: v.len={} p={:?}",v.len(),p);
    debug_assert!(!v.is_empty());
    let last_payload = v
        .last()
        .expect("parse_payload_list_fold: called with empty input");
    let next_payload_type = last_payload.hdr.next_payload_type;
    if p.hdr.payload_length < 4 {
        return Err(IPsecError::PayloadTooSmall);
    }
    match parse_ikev2_payload_with_type(p.payload, p.hdr.payload_length - 4, next_payload_type) {
        Ok((rem, p2)) => {
            // let (rem, p2) = parse_ikev2_payload_with_type(p.payload, p.hdr.payload_length - 4, next_payload_type)?;
            if !rem.is_empty() {
                return Err(IPsecError::ExtraBytesInPayload); // XXX should this be only a warning?
            }
            let payload = IkeV2Payload {
                hdr: p.hdr.clone(),
                content: p2,
            };
            v.push(payload);
            Ok(v)
        }
        Err(nom::Err::Error(e)) | Err(nom::Err::Failure(e)) => Err(IPsecError::NomError(e.code)),
        Err(nom::Err::Incomplete(_)) => Err(IPsecError::NomError(ErrorKind::Complete)),
    }
}

pub fn parse_ikev2_payload_list(
    i: &[u8],
    initial_type: IkePayloadType,
) -> IResult<&[u8], Result<Vec<IkeV2Payload>, IPsecError>> {
    // XXX fold manually, because fold_many1 requires accumulator to have Clone, and we don't want
    // XXX to implement that for IkeV2Payload
    let mut acc = Ok(vec![IkeV2Payload {
        hdr: IkeV2PayloadHeader {
            next_payload_type: initial_type,
            critical: false,
            reserved: 0,
            payload_length: 0,
        },
        content: IkeV2PayloadContent::Dummy,
    }]);
    #[allow(clippy::clone_double_ref)]
    let mut i = i.clone();
    loop {
        if i.is_empty() {
            break;
        }

        let (rem, p) = complete(parse_ikev2_payload_generic)(i)?;

        acc = parse_ikev2_payload_list_fold(acc, p);

        i = rem;
    }
    Ok((i, acc))
    // XXX should we split_first() the vector and return all but the first element ?
}

/// Parse an IKEv2 message
///
/// Parse the IKEv2 header and payload list
#[allow(clippy::type_complexity)]
pub fn parse_ikev2_message(
    i: &[u8],
) -> IResult<&[u8], (IkeV2Header, Result<Vec<IkeV2Payload>, IPsecError>)> {
    let (i, hdr) = parse_ikev2_header(i)?;
    if hdr.length < 28 {
        return Err(Err::Error(make_error(i, ErrorKind::Verify)));
    }
    let (i, msg) = map_parser(take(hdr.length - 28), |d| {
        parse_ikev2_payload_list(d, hdr.next_payload)
    })(i)?;
    Ok((i, (hdr, msg)))
}

#[cfg(test)]
mod tests {
    use crate::ikev2_parser::*;

    #[rustfmt::skip]
static IKEV2_INIT_REQ: &[u8] = &[
    0x01, 0xf8, 0xc3, 0xd4, 0xbb, 0x77, 0x3f, 0x2f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x21, 0x20, 0x22, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x48, 0x22, 0x00, 0x00, 0x30,
    0x00, 0x00, 0x00, 0x2c, 0x01, 0x01, 0x00, 0x04, 0x03, 0x00, 0x00, 0x0c, 0x01, 0x00, 0x00, 0x14,
    0x80, 0x0e, 0x00, 0x80, 0x03, 0x00, 0x00, 0x08, 0x03, 0x00, 0x00, 0x0c, 0x03, 0x00, 0x00, 0x08,
    0x02, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x08, 0x04, 0x00, 0x00, 0x1e, 0x28, 0x00, 0x00, 0x88,
    0x00, 0x1e, 0x00, 0x00, 0x8f, 0xe6, 0xf3, 0x6e, 0x88, 0x7b, 0x18, 0x9b, 0x5e, 0xce, 0xf2, 0x56,
    0xf9, 0x8d, 0x76, 0xaa, 0xcb, 0x07, 0xb3, 0xb9, 0x58, 0xee, 0x73, 0xea, 0x7b, 0x73, 0xb1, 0x04,
    0x7e, 0xa4, 0x2a, 0x4e, 0x44, 0x1f, 0xb9, 0x3e, 0xf9, 0xa9, 0xab, 0x0c, 0x54, 0x5a, 0xa7, 0x46,
    0x2e, 0x58, 0x3c, 0x06, 0xb2, 0xed, 0x91, 0x8d, 0x11, 0xca, 0x67, 0xdb, 0x21, 0x6b, 0xb8, 0xad,
    0xbf, 0x57, 0x3f, 0xba, 0x5a, 0xa6, 0x7d, 0x49, 0x83, 0x4b, 0xa9, 0x93, 0x6f, 0x4c, 0xe9, 0x66,
    0xcd, 0x57, 0x5c, 0xba, 0x07, 0x42, 0xfa, 0x0b, 0xe8, 0xb9, 0xd0, 0x25, 0xc4, 0xb9, 0xdf, 0x29,
    0xd7, 0xe4, 0x6e, 0xd6, 0x54, 0x78, 0xaa, 0x95, 0x02, 0xbf, 0x25, 0x55, 0x71, 0xfa, 0x9e, 0xcb,
    0x05, 0xea, 0x8f, 0x7b, 0x14, 0x0e, 0x1d, 0xdf, 0xb4, 0x03, 0x5f, 0x2d, 0x21, 0x66, 0x58, 0x6e,
    0x42, 0x72, 0x32, 0x03, 0x29, 0x00, 0x00, 0x24, 0xe3, 0x3b, 0x52, 0xaa, 0x6f, 0x6d, 0x62, 0x87,
    0x16, 0xd7, 0xab, 0xc6, 0x45, 0xa6, 0xcc, 0x97, 0x07, 0x43, 0x3d, 0x85, 0x83, 0xde, 0xab, 0x97,
    0xdb, 0xbf, 0x08, 0xce, 0x0f, 0xad, 0x59, 0x71, 0x29, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x40, 0x04,
    0xcc, 0xc0, 0x64, 0x5c, 0x1e, 0xeb, 0xc2, 0x1d, 0x09, 0x2b, 0xf0, 0x7f, 0xca, 0x34, 0xc3, 0xe6,
    0x2b, 0x20, 0xec, 0x8f, 0x29, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x40, 0x05, 0x15, 0x39, 0x75, 0x77,
    0xf5, 0x54, 0x87, 0xa3, 0x8f, 0xd8, 0xaf, 0x70, 0xb0, 0x9c, 0x20, 0x9c, 0xff, 0x4a, 0x37, 0xd1,
    0x29, 0x00, 0x00, 0x10, 0x00, 0x00, 0x40, 0x2f, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04,
    0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x40, 0x16
];

    #[test]
    fn test_ikev2_init_req() {
        let empty = &b""[..];
        let bytes = &IKEV2_INIT_REQ[0..28];
        let expected = Ok((
            empty,
            IkeV2Header {
                init_spi: 0x01f8c3d4bb773f2f,
                resp_spi: 0x0,
                next_payload: IkePayloadType::SecurityAssociation,
                maj_ver: 2,
                min_ver: 0,
                exch_type: IkeExchangeType::IKE_SA_INIT,
                flags: 0x8,
                msg_id: 0,
                length: 328,
            },
        ));
        let res = parse_ikev2_header(bytes);
        assert_eq!(res, expected);
    }

    static IKEV2_INIT_RESP: &[u8] = include_bytes!("../assets/ike-sa-init-resp.bin");

    #[test]
    fn test_ikev2_init_resp() {
        let bytes = IKEV2_INIT_RESP;
        let (rem, ref hdr) = parse_ikev2_header(bytes).expect("parsing header failed");
        let (rem2, res_p) =
            parse_ikev2_payload_list(rem, hdr.next_payload).expect("parsing payload failed");
        assert!(rem2.is_empty());
        let p = res_p.expect("parsing payload failed");
        // there are 5 items + dummy => 6
        assert_eq!(p.len(), 6);
        // first one is always dummy
        assert_eq!(p[0].content, IkeV2PayloadContent::Dummy);
    }

    #[rustfmt::skip]
static IKEV2_PAYLOAD_SA: &[u8] = &[
    0x22, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00, 0x24, 0x01, 0x01, 0x00, 0x03, 0x03, 0x00, 0x00, 0x0c,
    0x01, 0x00, 0x00, 0x14, 0x80, 0x0e, 0x00, 0x80, 0x03, 0x00, 0x00, 0x08, 0x02, 0x00, 0x00, 0x05,
    0x00, 0x00, 0x00, 0x08, 0x04, 0x00, 0x00, 0x1e
];

    #[test]
    fn test_ikev2_payload_sa() {
        let bytes = IKEV2_PAYLOAD_SA;
        let expected1 = IkeV2GenericPayload {
            hdr: IkeV2PayloadHeader {
                next_payload_type: IkePayloadType::KeyExchange,
                critical: false,
                reserved: 0,
                payload_length: 40,
            },
            payload: &bytes[4..],
        };
        let (_, res) = parse_ikev2_payload_generic(bytes).expect("Failed to parse");
        assert_eq!(res, expected1);
        let attrs1 = &[0x80, 0x0e, 0x00, 0x80];
        let expected2 = IkeV2PayloadContent::SA(vec![IkeV2Proposal {
            last: 0,
            reserved: 0,
            proposal_length: 36,
            proposal_num: 1,
            protocol_id: ProtocolID::IKE,
            spi_size: 0,
            num_transforms: 3,
            spi: None,
            transforms: vec![
                IkeV2RawTransform {
                    last: 3,
                    reserved1: 0,
                    transform_length: 12,
                    transform_type: IkeTransformType::EncryptionAlgorithm,
                    reserved2: 0,
                    transform_id: 20,
                    attributes: Some(attrs1),
                },
                IkeV2RawTransform {
                    last: 3,
                    reserved1: 0,
                    transform_length: 8,
                    transform_type: IkeTransformType::PseudoRandomFunction,
                    reserved2: 0,
                    transform_id: 5,
                    attributes: None,
                },
                IkeV2RawTransform {
                    last: 0,
                    reserved1: 0,
                    transform_length: 8,
                    transform_type: IkeTransformType::DiffieHellmanGroup,
                    reserved2: 0,
                    transform_id: 30,
                    attributes: None,
                },
            ],
        }]);

        let (rem, res2) = parse_ikev2_payload_sa(res.payload, 0).expect("Failed to parse");
        assert!(rem.is_empty());
        assert_eq!(res2, expected2);
    }

    #[test]
    fn test_ikev2_parse_payload_many() {
        // let empty = &b""[..];
        let bytes = &IKEV2_INIT_REQ[28..];
        let res = parse_ikev2_payload_list(bytes, IkePayloadType::SecurityAssociation);
        println!("{:?}", res);
    }
}
