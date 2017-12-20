use std::net::{IpAddr,Ipv4Addr,Ipv6Addr};
use enum_primitive::FromPrimitive;
use ikev2_transforms::*;

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
/// Defined in [RFC7296] section 3.3.1
#[derive(Debug,PartialEq)]
#[repr(u8)]
pub enum IkeProtocolID {
    Ike = 1,
    Ah = 2,
    Esp = 3,
}
}

enum_from_primitive! {
/// Defined in [RFC7296] section 3.6
/// See also http://www.iana.org/assignments/ikev2-parameters/ikev2-parameters.xhtml
#[derive(Debug,PartialEq)]
#[repr(u8)]
pub enum IkeCertificateEncodingType {
    Pkcs7X509 = 1,
    Pgp = 2,
    Dns = 3,
    X509Sig = 4,
    // 5 is reserved
    Kerberos = 6,
    Crl = 7,
    Arl = 8,
    SpkiCert = 9,
    X509Attr = 10,
    RawRsa = 11,
    HashUrlX509Cert = 12,
    HashUrlX509Bundle = 13,
    OCSPContent = 14,
    // Raw public key support, defined in [RFC7670]
    RawPublicKey = 15,
}
}

pub const IKEV2_FLAG_INITIATOR : u8 = 0b1000;
pub const IKEV2_FLAG_VERSION : u8   = 0b10000;
pub const IKEV2_FLAG_RESPONSE : u8  = 0b100000;

/// Defined in [RFC7296]
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

enum_from_primitive! {
#[derive(Debug,PartialEq)]
#[repr(u8)]
pub enum IkePayloadType {
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
}

/// Defined in [RFC7296]
#[derive(Debug,PartialEq)]
pub struct IkeV2GenericPayload<'a> {
    pub hdr: IkeV2PayloadHeader,
    pub payload: &'a[u8],
}

/// Defined in [RFC7296]
#[derive(Clone,Debug,PartialEq)]
pub struct IkeV2Proposal<'a> {
    pub last: u8,
    pub reserved: u8,
    pub proposal_length: u16,
    pub proposal_num: u8,
    pub protocol_id: u8,
    pub spi_size: u8,
    pub num_transforms: u8,
    pub spi: Option<&'a[u8]>,
    pub transforms: Vec<IkeV2RawTransform<'a>>,
}

/// Defined in [RFC7296]
#[derive(Debug,PartialEq)]
pub struct KeyExchangePayload<'a> {
    pub dh_group: u16,
    pub reserved: u16,
    pub kex_data: &'a[u8],
}

/// Defined in [RFC7296] section 3.5
#[derive(Debug,PartialEq)]
pub struct IdentificationPayload<'a> {
    pub id_type: u8,
    pub reserved1: u8,
    pub reserved2: u16,
    pub ident_data: &'a[u8],
}

/// Defined in [RFC7296] section 3.7
#[derive(Debug,PartialEq)]
pub struct CertificatePayload<'a> {
    pub cert_encoding: u8,
    pub cert_data: &'a[u8],
}

/// Defined in [RFC7296] section 3.7
#[derive(Debug,PartialEq)]
pub struct CertificateRequestPayload<'a> {
    pub cert_encoding: u8,
    pub ca_data: &'a[u8],
}

/// Defined in [RFC7296] section 3.8
#[derive(Debug,PartialEq)]
pub struct AuthenticationPayload<'a> {
    pub auth_method: u8,
    pub auth_data: &'a[u8],
}


/// Defined in [RFC7296] section 3.9
#[derive(PartialEq)]
pub struct NoncePayload<'a> {
    pub nonce_data: &'a[u8],
}

/// Defined in [RFC7296] section 3.10
#[derive(PartialEq)]
pub struct NotifyPayload<'a> {
    pub protocol_id: u8,
    pub spi_size: u8,
    pub notify_type: u16,
    pub spi: Option<&'a[u8]>,
    pub notify_data: Option<&'a[u8]>,
}

/// Defined in [RFC7296] section 3.11
#[derive(Debug,PartialEq)]
pub struct DeletePayload<'a> {
    pub protocol_id: u8,
    pub spi_size: u8,
    pub num_spi: u16,
    pub spi: &'a[u8],
}

/// Defined in [RFC7296] section 3.12
#[derive(Debug,PartialEq)]
pub struct VendorIDPayload<'a> {
    pub vendor_id: &'a[u8],
}

enum_from_primitive! {
/// Defined in [RFC7296] section 3.13.1
#[derive(Debug,PartialEq)]
#[repr(u8)]
pub enum TSType {
    IPv4AddrRange = 7,
    IPv6AddrRange = 8,
}
}

/// Defined in [RFC7296] section 3.13.1
#[derive(Debug,PartialEq)]
pub struct TrafficSelector<'a> {
    pub ts_type: u8,
    pub ip_proto_id: u8,
    pub sel_length: u16,
    pub start_port: u16,
    pub end_port: u16,
    pub start_addr: &'a[u8],
    pub end_addr: &'a[u8],
}

fn ipv4_from_slice(b:&[u8]) -> Ipv4Addr {
    Ipv4Addr::new(b[0], b[1], b[2], b[3])
}

fn ipv6_from_slice(b:&[u8]) -> Ipv6Addr {
    Ipv6Addr::new(
        (b[0] as u16) << 8 | (b[1] as u16),
        (b[2] as u16) << 8 | (b[3] as u16),
        (b[4] as u16) << 8 | (b[5] as u16),
        (b[6] as u16) << 8 | (b[7] as u16),
        (b[8] as u16) << 8 | (b[9] as u16),
        (b[10] as u16) << 8 | (b[11] as u16),
        (b[12] as u16) << 8 | (b[13] as u16),
        (b[14] as u16) << 8 | (b[15] as u16),
    )
}

impl<'a> TrafficSelector<'a> {
    pub fn get_ts_type(&self) -> Option<TSType> {
        TSType::from_u8(self.ts_type)
    }

    pub fn get_start_addr(&self) -> Option<IpAddr> {
        match self.ts_type {
            7 => Some(IpAddr::V4(ipv4_from_slice(self.start_addr))),
            8 => Some(IpAddr::V6(ipv6_from_slice(self.start_addr))),
            _ => None,
        }
    }

    pub fn get_end_addr(&self) -> Option<IpAddr> {
        match self.ts_type {
            7 => Some(IpAddr::V4(ipv4_from_slice(self.end_addr))),
            8 => Some(IpAddr::V6(ipv6_from_slice(self.end_addr))),
            _ => None,
        }
    }
}

/// Defined in [RFC7296] section 3.13
#[derive(Debug,PartialEq)]
pub struct TrafficSelectorPayload<'a> {
    pub num_ts: u8,
    pub reserved: &'a[u8], // 3 bytes
    pub ts: Vec<TrafficSelector<'a>>,
}

/// Defined in [RFC7296] section 3.2
#[derive(Debug,PartialEq)]
pub enum IkeV2PayloadContent<'a> {
    SA(Vec<IkeV2Proposal<'a>>),
    KE(KeyExchangePayload<'a>),
    IDi(IdentificationPayload<'a>),
    IDr(IdentificationPayload<'a>),
    Certificate(CertificatePayload<'a>),
    CertificateRequest(CertificateRequestPayload<'a>),
    Authentication(AuthenticationPayload<'a>),
    Nonce(NoncePayload<'a>),
    Notify(NotifyPayload<'a>),
    Delete(DeletePayload<'a>),
    VendorID(VendorIDPayload<'a>),
    TSi(TrafficSelectorPayload<'a>),
    TSr(TrafficSelectorPayload<'a>),

    Unknown(&'a[u8]),

    Dummy,
}

/// Defined in [RFC7296]
#[derive(Clone,Debug,PartialEq)]
pub struct IkeV2PayloadHeader {
    pub next_payload_type: u8,
    pub critical: bool,
    pub reserved: u8,
    pub payload_length: u16,
}

impl IkeV2PayloadHeader {
    pub fn get_next_payload_type(&self) -> Option<IkePayloadType> {
        IkePayloadType::from_u8(self.next_payload_type)
    }
}

/// Defined in [RFC7296]
#[derive(Debug,PartialEq)]
pub struct IkeV2Payload<'a> {
    pub hdr: IkeV2PayloadHeader,
    pub content: IkeV2PayloadContent<'a>,
}
