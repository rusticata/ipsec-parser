use nom::*;

enum_from_primitive! {
#[derive(Debug,PartialEq)]
#[repr(u8)]
pub enum IkeExchangeType {
    IkeSAInit = 34,
    IkeAuth = 35,
    CreateChildSA = 36,
    Informational = 37,
}
}

enum_from_primitive! {
/// Defined in [RFC5996] section 3.3.2
#[derive(Debug,PartialEq)]
#[repr(u8)]
pub enum IkeTransformType {
    EncryptionAlgorithm = 1,
    PseudoRandomFunction = 2,
    IntegrityAlgorithm = 3,
    DiffieHellmanGroup = 4,
    ExtendedSequenceNumbers = 5,
}
}

enum_from_primitive! {
/// Defined in [RFC5996] section 3.3.2
#[derive(Debug,PartialEq)]
#[repr(u8)]
pub enum IkeTransformEncType {
    DesIV64 = 1,
    Des = 2,
    TripleDes = 3,
    Rc5 = 4,
    Idea = 5,
    Cast = 6,
    Blowfish = 7,
    TripleIdea = 8,
    DesIV32 = 9,
    Null = 10,
    AesCBC = 11,
    AesCTR = 12,
}
}

enum_from_primitive! {
/// Defined in [RFC5996] section 3.3.2
#[derive(Debug,PartialEq)]
#[repr(u8)]
pub enum IkeTransformPRFType {
    HmacMd5 = 1,
    HmacSha1 = 2,
    HmacTiger = 3,
}
}

enum_from_primitive! {
/// Defined in [RFC5996] section 3.3.2
#[derive(Debug,PartialEq)]
#[repr(u8)]
pub enum IkeTransformAuthType {
    None = 0,
    HmacMd5s96 = 1,
    HmacSha1s96 = 2,
    HmacDesMac = 3,
    HmacKpdkMd5 = 4,
    HmacAesXCBC96 = 5,
}
}

enum_from_primitive! {
/// Defined in [RFC5996] section 3.3.2
#[derive(Debug,PartialEq)]
#[repr(u8)]
pub enum IkeTransformDHType {
    None = 0,
    Modp768 = 1,
    Modp1024 = 2,
    Modp1536 = 5,
    Modp2048 = 14,
    Modp3072 = 15,
    Modp4096 = 16,
    Modp6144 = 17,
    Modp8192 = 18,
}
}

enum_from_primitive! {
/// Defined in [RFC5996] section 3.3.2
#[derive(Debug,PartialEq)]
#[repr(u8)]
pub enum IkeTransformESNType {
    NoESN = 0,
    ESN = 1,
}
}

/// Defined in [RFC5996]
#[derive(Debug,PartialEq)]
pub struct IkeV2Header<'a> {
    pub init_spi: &'a[u8],
    pub resp_spi: &'a[u8],
    pub next_payload: u8,
    pub maj_ver: u8,
    pub min_ver: u8,
    pub exch_type: u8,
    pub flags: u8,
    pub msg_id: u32,
    pub length: u32,
}

#[derive(Debug,PartialEq)]
#[repr(u8)]
pub enum IkeNextPayloadType {
    NoNextPayload = 0,
    SecurityAssociation = 33,
    KeyExchange = 34,
    IdentInitiator = 35,
    IdentResponder = 36,
    Certificate = 37,
    CertificateRequest = 38,
    Authentication = 39,
    Nonce = 40,
    Notify = 41,
    Delete = 42,
    VendorID = 43,
    TrafficSelectorInitiator = 44,
    TrafficSelectorResponder = 45,
    EncryptedAndAuthenticated = 46,
    Configuration = 47,
    ExtensibleAuthentication = 48,
}

/// Defined in [RFC5996]
#[derive(Debug,PartialEq)]
pub struct IkeV2GenericPayload<'a> {
    pub hdr: IkeV2PayloadHeader,
    pub payload: &'a[u8],
}

/// Defined in [RFC5996]
#[derive(Debug,PartialEq)]
pub struct IkeV2Transform<'a> {
    pub last: u8,
    pub reserved1: u8,
    pub transform_length: u16,
    pub transform_type: u8,
    pub reserved2: u8,
    pub transform_id: u16,
    pub attributes: Option<&'a[u8]>,
}

/// Defined in [RFC5996]
#[derive(Debug,PartialEq)]
pub struct IkeV2Proposal<'a> {
    pub last: u8,
    pub reserved: u8,
    pub proposal_length: u16,
    pub proposal_num: u8,
    pub protocol_id: u8,
    pub spi_size: u8,
    pub num_transforms: u8,
    pub spi: Option<&'a[u8]>,
    pub transforms: Vec<IkeV2Transform<'a>>,
}

/// Defined in [RFC5996]
#[derive(Debug,PartialEq)]
pub struct KeyExchangePayload<'a> {
    pub dh_group: u16,
    pub reserved: u16,
    pub kex_data: &'a[u8],
}

/// Defined in [RFC5996] section 3.5
#[derive(Debug,PartialEq)]
pub struct IdentificationPayload<'a> {
    pub id_type: u8,
    pub reserved1: u8,
    pub reserved2: u16,
    pub ident_data: &'a[u8],
}

// XXX Certificate

// XXX CertificateRequest

// XXX Authentication

/// Defined in [RFC5996] section 3.9
#[derive(Debug,PartialEq)]
pub struct NoncePayload<'a> {
    pub nonce_data: &'a[u8],
}

/// Defined in [RFC5996] section 3.2
#[derive(Debug,PartialEq)]
pub enum IkeV2PayloadContent<'a> {
    SA(Vec<IkeV2Proposal<'a>>),
    KE(KeyExchangePayload<'a>),
    IDi(IdentificationPayload<'a>),
    IDr(IdentificationPayload<'a>),

    Nonce(NoncePayload<'a>),

    Unknown(&'a[u8]),

    Dummy,
}

/// Defined in [RFC5996]
#[derive(Clone,Debug,PartialEq)]
pub struct IkeV2PayloadHeader {
    pub next_payload_type: u8,
    pub critical: bool,
    pub reserved: u8,
    pub payload_length: u16,
}

/// Defined in [RFC5996]
#[derive(Debug,PartialEq)]
pub struct IkeV2Payload<'a> {
    pub hdr: IkeV2PayloadHeader,
    pub content: IkeV2PayloadContent<'a>,
}


named!(pub parse_ikev2_header<IkeV2Header>,
    chain!(
        init_spi: take!(8) ~
        resp_spi: take!(8) ~
        np: be_u8 ~
        vers: bits!(
            tuple!(take_bits!(u8,4),take_bits!(u8,4))
            ) ~
        ex: be_u8 ~
        flags: be_u8 ~
        id: be_u32 ~
        l: be_u32,
        || {
            IkeV2Header{
                init_spi: init_spi,
                resp_spi: resp_spi,
                next_payload: np,
                maj_ver: vers.0,
                min_ver: vers.1,
                exch_type: ex,
                flags: flags,
                msg_id: id,
                length: l,
            }
        }
    )
);

named!(pub parse_ikev2_payload_generic<IkeV2GenericPayload>,
    chain!(
        np_type: be_u8 ~
        b: bits!(
            tuple!(take_bits!(u8,1),take_bits!(u8,7))
            ) ~
        len: be_u16 ~
        data: take!(len-4),
        || {
            IkeV2GenericPayload{
                hdr: IkeV2PayloadHeader {
                    next_payload_type: np_type,
                    critical: b.0 == 1,
                    reserved: b.1,
                    payload_length: len,
                },
                payload: data,
            }
        }
    )
);

named!(pub parse_ikev2_transform<IkeV2Transform>,
    chain!(
        last: be_u8 ~
        reserved1: be_u8 ~
        transform_length: be_u16 ~
        transform_type: be_u8 ~
        reserved2: be_u8 ~
        transform_id: be_u16 ~
        attributes: cond!(transform_length > 8,take!(transform_length-8)),
        || {
            IkeV2Transform{
                last: last,
                reserved1:reserved1,
                transform_length: transform_length,
                transform_type: transform_type,
                reserved2: reserved2,
                transform_id: transform_id,
                attributes: attributes,
            }
        }
    )
);

named!(pub parse_ikev2_proposal<IkeV2Proposal>,
    chain!(
        last: be_u8 ~
        reserved: be_u8 ~
        p_len: be_u16 ~
        p_num: be_u8 ~
        proto_id: be_u8 ~
        spi_size: be_u8 ~
        num_transforms: be_u8 ~
        spi: cond!(spi_size > 0,take!(spi_size)) ~
        transforms: flat_map!(
            take!( p_len - (8u16+spi_size as u16) ),
            many_m_n!(num_transforms as usize,num_transforms as usize,parse_ikev2_transform)
            ),
        || { IkeV2Proposal{
            last:last,
            reserved:reserved,
            proposal_length: p_len,
            proposal_num: p_num,
            protocol_id: proto_id,
            spi_size: spi_size,
            num_transforms: num_transforms,
            spi: spi,
            transforms: transforms,
        }}
    )
);

pub fn parse_ikev2_payload_sa<'a>(i: &'a[u8], _length: u16) -> IResult<&'a[u8],IkeV2PayloadContent<'a>> {
    map!(i,
        many1!(parse_ikev2_proposal),
        |v|{ IkeV2PayloadContent::SA(v) }
    )
}

pub fn parse_ikev2_payload_kex<'a>(i: &'a[u8], length: u16) -> IResult<&'a[u8],IkeV2PayloadContent<'a>> {
    chain!(i,
        dh: be_u16 ~
        reserved: be_u16 ~
        data: take!(length-4),
        || {
            IkeV2PayloadContent::KE(
                KeyExchangePayload{
                    dh_group: dh,
                    reserved: reserved,
                    kex_data: data,
                }
            )
        })
}

pub fn parse_ikev2_payload_ident_init<'a>(i: &'a[u8], length: u16) -> IResult<&'a[u8],IkeV2PayloadContent<'a>> {
    chain!(i,
        id_type: be_u8 ~
        reserved1: be_u8 ~
        reserved2: be_u16 ~
        data: take!(length-4),
        || {
            IkeV2PayloadContent::IDi(
                IdentificationPayload{
                    id_type: id_type,
                    reserved1: reserved1,
                    reserved2: reserved2,
                    ident_data: data,
                }
            )
        })
}

pub fn parse_ikev2_payload_ident_resp<'a>(i: &'a[u8], length: u16) -> IResult<&'a[u8],IkeV2PayloadContent<'a>> {
    chain!(i,
        id_type: be_u8 ~
        reserved1: be_u8 ~
        reserved2: be_u16 ~
        data: take!(length-4),
        || {
            IkeV2PayloadContent::IDr(
                IdentificationPayload{
                    id_type: id_type,
                    reserved1: reserved1,
                    reserved2: reserved2,
                    ident_data: data,
                }
            )
        })
}

// XXX Certificate

// XXX CertificateRequest

// XXX Authentication

pub fn parse_ikev2_payload_nonce<'a>(i: &'a[u8], length: u16) -> IResult<&'a[u8],IkeV2PayloadContent<'a>> {
    chain!(i,
        data: take!(length),
        || {
            IkeV2PayloadContent::Nonce(
                NoncePayload{
                    nonce_data: data,
                }
            )
        })
}

pub fn parse_ikev2_payload_unknown<'a>(i: &'a[u8], length: u16) -> IResult<&'a[u8],IkeV2PayloadContent<'a>> {
    map!(i, take!(length), |d| { IkeV2PayloadContent::Unknown(d) })
}

pub fn parse_ikev2_payload_with_type<'a>(i: &'a[u8], length: u16, next_payload_type: u8) -> IResult<&'a[u8],IkeV2PayloadContent<'a>> {
    let f = match next_payload_type {
        33 => parse_ikev2_payload_sa,
        34 => parse_ikev2_payload_kex,
        35 => parse_ikev2_payload_ident_init,
        36 => parse_ikev2_payload_ident_resp,
        40 => parse_ikev2_payload_nonce,
        _  => parse_ikev2_payload_unknown,
    };
    flat_map!(i,take!(length),call!(f,length))
}

fn parse_ikev2_payload_list_fold<'a>(mut v: Vec<IkeV2Payload<'a>>, p: IkeV2GenericPayload<'a>) -> Vec<IkeV2Payload<'a>> {
    // println!("parse_payload_list_fold: v.len={} p={:?}",v.len(),p);
    let next_payload_type = match v.last() {
        Some(el) => el.hdr.next_payload_type,
        // XXX how to return error in fold_many1 ?
        None => { assert!(false); 0 },
    };
    match parse_ikev2_payload_with_type(p.payload,p.hdr.payload_length-4,next_payload_type) {
        IResult::Done(rem,p2) => {
            // println!("rem: {:?}",rem);
            // println!("p2: {:?}",p2);
            assert!(rem.len() == 0);
            let payload = IkeV2Payload {
                hdr: p.hdr.clone(),
                content: p2,
            };
            v.push(payload);
        },
        _ => {
            // XXX how to return error in fold_many1 ?
            assert!(false);
        },
    };
    v
}

pub fn parse_ikev2_payload_list<'a>(i: &'a[u8], initial_type: u8) -> IResult<&'a[u8],Vec<IkeV2Payload<'a>>> {
    fold_many1!(i,
        parse_ikev2_payload_generic,
        vec![
            IkeV2Payload{
                hdr:IkeV2PayloadHeader{next_payload_type:initial_type,critical:false,reserved:0,payload_length:0},
                content:IkeV2PayloadContent::Dummy,
            },
        ],
        parse_ikev2_payload_list_fold
    )
    // XXX should we split_first() the vector and return all but the first element ?
}

#[cfg(test)]
mod tests {
    use ipsec::*;
    use nom::IResult;

static IKEV2_INIT_REQ: &'static [u8] = &[
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
    let expected = IResult::Done(empty,IkeV2Header{
        init_spi: &bytes[0..8],
        resp_spi: &bytes[8..16],
        next_payload: 33,
        maj_ver: 2,
        min_ver: 0,
        exch_type: 34,
        flags: 0x8,
        msg_id: 0,
        length: 328,
    });
    let res = parse_ikev2_header(&bytes);
    assert_eq!(res, expected);
}

static IKEV2_INIT_RESP: &'static [u8] = &[
    0x01, 0xf8, 0xc3, 0xd4, 0xbb, 0x77, 0x3f, 0x2f, 0x71, 0xac, 0x0e, 0x15, 0x6b, 0xad, 0x60, 0x46,
    0x21, 0x20, 0x22, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x5d, 0x22, 0x00, 0x00, 0x28,
    0x00, 0x00, 0x00, 0x24, 0x01, 0x01, 0x00, 0x03, 0x03, 0x00, 0x00, 0x0c, 0x01, 0x00, 0x00, 0x14,
    0x80, 0x0e, 0x00, 0x80, 0x03, 0x00, 0x00, 0x08, 0x02, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x08,
    0x04, 0x00, 0x00, 0x1e, 0x28, 0x00, 0x00, 0x88, 0x00, 0x1e, 0x00, 0x00, 0x41, 0xee, 0xeb, 0x22,
    0xb8, 0x6c, 0x87, 0xa4, 0xc8, 0xa9, 0xe9, 0x54, 0xf8, 0x81, 0x61, 0x2c, 0x8c, 0xfb, 0xaf, 0xb0,
    0x38, 0x62, 0x1d, 0x7f, 0xc6, 0x97, 0x3d, 0x80, 0x7b, 0x29, 0x26, 0x0d, 0x63, 0x44, 0x4d, 0xdb,
    0x92, 0x22, 0x5c, 0x6b, 0xab, 0xf5, 0x60, 0x4d, 0x37, 0xef, 0x4a, 0xe3, 0xb7, 0x53, 0x88, 0x9c,
    0xb0, 0xce, 0x38, 0xca, 0xc1, 0xb7, 0x9a, 0x74, 0xad, 0x00, 0x78, 0x0f, 0x39, 0x45, 0x78, 0x97,
    0x98, 0xf5, 0xc3, 0x26, 0x0c, 0x1c, 0x8e, 0x77, 0xd3, 0x34, 0xc8, 0xf5, 0xad, 0xe4, 0xe2, 0xbb,
    0x35, 0xce, 0x4e, 0xf2, 0xf9, 0x25, 0x1c, 0x06, 0xe2, 0x89, 0x8b, 0x28, 0xed, 0xc6, 0xa3, 0xa6,
    0x0b, 0xcd, 0x63, 0xb9, 0xe9, 0x26, 0x40, 0xe3, 0xb4, 0xa5, 0x14, 0x78, 0x7a, 0xcd, 0x3c, 0x5f,
    0xe8, 0x9c, 0xe4, 0xd1, 0x06, 0xf8, 0x9a, 0x49, 0x24, 0x31, 0x21, 0x60, 0x29, 0x00, 0x00, 0x24,
    0xb1, 0x74, 0x30, 0xe4, 0xc8, 0x43, 0x93, 0x3f, 0x4f, 0x2f, 0xaf, 0x06, 0x19, 0xcb, 0x9f, 0x63,
    0xc2, 0xa6, 0xda, 0x2d, 0x52, 0xbd, 0x60, 0x61, 0xb0, 0x08, 0x7a, 0x20, 0x9e, 0xa3, 0x27, 0x05,
    0x29, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x40, 0x04, 0xb0, 0x3f, 0xd9, 0x96, 0x0d, 0x92, 0x2b, 0xbe,
    0xa4, 0x05, 0x5e, 0xbc, 0x51, 0x96, 0xd6, 0x9c, 0x0a, 0x15, 0xa2, 0x4a, 0x26, 0x00, 0x00, 0x1c,
    0x00, 0x00, 0x40, 0x05, 0x72, 0xee, 0xc3, 0xa6, 0xbc, 0x01, 0x6b, 0x6d, 0x97, 0x5f, 0x90, 0x1c,
    0x74, 0x81, 0x88, 0xec, 0xde, 0x59, 0xb4, 0x09, 0x29, 0x00, 0x00, 0x2d, 0x04, 0x29, 0xec, 0xca,
    0x39, 0xe7, 0x26, 0xb9, 0xe6, 0x7e, 0x59, 0x36, 0x5e, 0x99, 0xb0, 0x98, 0x02, 0xca, 0x5a, 0x02,
    0x3c, 0xed, 0xae, 0x2f, 0x6b, 0x43, 0x0e, 0x78, 0x20, 0x7b, 0x5f, 0x7b, 0x4f, 0xd8, 0x59, 0xe3,
    0xf3, 0x8c, 0x4b, 0x0b, 0x87, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x40, 0x14
];

static IKEV2_PAYLOAD_SA: &'static [u8] = &[
    0x22, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00, 0x24, 0x01, 0x01, 0x00, 0x03, 0x03, 0x00, 0x00, 0x0c,
    0x01, 0x00, 0x00, 0x14, 0x80, 0x0e, 0x00, 0x80, 0x03, 0x00, 0x00, 0x08, 0x02, 0x00, 0x00, 0x05,
    0x00, 0x00, 0x00, 0x08, 0x04, 0x00, 0x00, 0x1e
];

#[test]
fn test_ikev2_payload_sa() {
    let empty = &b""[..];
    let bytes = IKEV2_PAYLOAD_SA;
    let expected1 = IResult::Done(empty,IkeV2GenericPayload{
        hdr: IkeV2PayloadHeader {
            next_payload_type: IkeNextPayloadType::KeyExchange as u8,
            critical: false,
            reserved: 0,
            payload_length: 40,
        },
        payload: &bytes[4..],
    });
    let res = parse_ikev2_payload_generic(&bytes);
    assert_eq!(res, expected1);
    let attrs1 = &[0x80, 0x0e, 0x00, 0x80];
    let expected2 = IResult::Done(empty,IkeV2PayloadContent::SA(vec![
        IkeV2Proposal {
            last: 0,
            reserved: 0,
            proposal_length: 36,
            proposal_num: 1,
            protocol_id: 1,
            spi_size: 0,
            num_transforms: 3,
            spi: None,
            transforms: vec![
                IkeV2Transform{
                    last: 3,
                    reserved1: 0,
                    transform_length: 12,
                    transform_type: 1,
                    reserved2: 0,
                    transform_id: 20,
                    attributes: Some(attrs1),
                },
                IkeV2Transform{
                    last: 3,
                    reserved1: 0,
                    transform_length: 8,
                    transform_type: 2,
                    reserved2: 0,
                    transform_id: 5,
                    attributes: None,
                },
                IkeV2Transform{
                    last: 0,
                    reserved1: 0,
                    transform_length: 8,
                    transform_type: 4,
                    reserved2: 0,
                    transform_id: 30,
                    attributes: None,
                },
            ],
        },
    ]
    ));
    match res {
        IResult::Done(_,ref hdr) => {
            let res2 = parse_ikev2_payload_sa(hdr.payload,0);
            assert_eq!(res2, expected2);
        },
        _ => assert!(false),
    };
}

#[test]
fn test_ikev2_parse_payload_many() {
    // let empty = &b""[..];
    let bytes = &IKEV2_INIT_REQ[28..];
    let res = parse_ikev2_payload_list(&bytes,33);
    println!("{:?}",res);
}

}
