use std::convert::From;
use enum_primitive::FromPrimitive;

enum_from_primitive! {
/// Defined in [RFC7296] section 3.3.2
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
/// Defined in [RFC7296] section 3.3.2
/// See also http://www.iana.org/assignments/ikev2-parameters/ikev2-parameters.xhtml
#[derive(Debug,PartialEq)]
#[repr(u16)]
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
    // 10 is reserved
    Null = 11,
    AesCBC = 12,
    AesCTR = 13,
    AesCCM8 = 14,
    AesCCM12 = 15,
    AesCCM16 = 16,
    // 17 is unassigned
    AesGCM8 = 18,
    AesGCM12 = 19,
    AesGCM16 = 20,
    NullAuthAesGCMMac = 21,
    // 22 is reserved
    CamelliaCBC = 23,
    CamelliaCTR = 24,
    CamelliaCCM8 = 25,
    CamelliaCCM12 = 26,
    CamelliaCCM16 = 27,
    Chacha20Poly1305 = 28, // [RFC7634]
}
}

impl IkeTransformEncType {
    pub fn is_aead(&self) -> bool {
        match *self {
            IkeTransformEncType::AesCCM8 |
            IkeTransformEncType::AesCCM12 |
            IkeTransformEncType::AesCCM16 |
            IkeTransformEncType::AesGCM8 |
            IkeTransformEncType::AesGCM12 |
            IkeTransformEncType::AesGCM16 |
            IkeTransformEncType::CamelliaCCM8 |
            IkeTransformEncType::CamelliaCCM12 |
            IkeTransformEncType::CamelliaCCM16 |
            IkeTransformEncType::Chacha20Poly1305 => true,
            _ => false,
        }
    }
}

enum_from_primitive! {
/// Defined in [RFC7296] section 3.3.2
/// See also http://www.iana.org/assignments/ikev2-parameters/ikev2-parameters.xhtml
#[derive(Debug,PartialEq)]
#[repr(u16)]
pub enum IkeTransformPRFType {
    HmacMd5 = 1,
    HmacSha1 = 2,
    HmacTiger = 3,
    Aes128XCBC = 4,
    HmacSha256 = 5,
    HmacSha384 = 6,
    HmacSha512 = 7,
    Aes128CMAC = 8,
}
}

enum_from_primitive! {
/// Defined in [RFC7296] section 3.3.2
#[derive(Debug,PartialEq)]
#[repr(u16)]
pub enum IkeTransformAuthType {
    None = 0,
    HmacMd5s96 = 1,
    HmacSha1s96 = 2,
    DesMac = 3,
    KpdkMd5 = 4,
    AesXCBC96 = 5,
    HmacMd5s128 = 6,
    HmacMd5s160 = 7,
    AesCMAC96 = 8,
    Aes128GMAC = 9,
    Aes192GMAC = 10,
    Aes256GMAC = 11,
    HmacSha256s128 = 12,
    HmacSha384s192 = 13,
    HmacSha512s256 = 14,
}
}

enum_from_primitive! {
/// Defined in [RFC7296] section 3.3.2
/// See also http://www.iana.org/assignments/ikev2-parameters/ikev2-parameters.xhtml
#[derive(Debug,PartialEq)]
#[repr(u16)]
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
    Ecp256 = 19,
    Ecp384 = 20,
    Ecp521 = 21,
    Modp1024s160 = 22,
    Modp2048s224 = 23,
    Modp2048s256 = 24,
    Ecp192 = 25,
    Ecp224 = 26,
    BrainpoolP224r1 = 27,
    BrainpoolP256r1 = 28,
    BrainpoolP384r1 = 29,
    BrainpoolP512r1 = 30,
    Curve25519 = 31,
    Curve448 = 32,
}
}

enum_from_primitive! {
/// Defined in [RFC7296] section 3.3.2
#[derive(Debug,PartialEq)]
#[repr(u16)]
pub enum IkeTransformESNType {
    NoESN = 0,
    ESN = 1,
}
}

/// Defined in [RFC7296]
#[derive(Clone,PartialEq)]
pub struct IkeV2RawTransform<'a> {
    pub last: u8,
    pub reserved1: u8,
    pub transform_length: u16,
    pub transform_type: u8,
    pub reserved2: u8,
    pub transform_id: u16,
    pub attributes: Option<&'a[u8]>,
}

/// Defined in [RFC7296]
#[derive(Debug,PartialEq)]
pub enum IkeV2Transform {
    Encryption(IkeTransformEncType),
    PRF(IkeTransformPRFType),
    Auth(IkeTransformAuthType),
    DH(IkeTransformDHType),
    ESN(IkeTransformESNType),
    /// Unknown tranform (type,id)
    Unknown(u8,u16),
}

impl<'a> From<&'a IkeV2RawTransform<'a>> for IkeV2Transform {
    fn from(r: &IkeV2RawTransform) -> IkeV2Transform {
        match IkeTransformType::from_u8(r.transform_type) {
            Some(IkeTransformType::EncryptionAlgorithm) => {
                match IkeTransformEncType::from_u16(r.transform_id) {
                    Some(x) => IkeV2Transform::Encryption(x),
                    _       => IkeV2Transform::Unknown(r.transform_type,r.transform_id),
                }
            },
            Some(IkeTransformType::PseudoRandomFunction) => {
                match IkeTransformPRFType::from_u16(r.transform_id) {
                    Some(x) => IkeV2Transform::PRF(x),
                    _       => IkeV2Transform::Unknown(r.transform_type,r.transform_id),
                }
            },
            Some(IkeTransformType::IntegrityAlgorithm) => {
                match IkeTransformAuthType::from_u16(r.transform_id) {
                    Some(x) => IkeV2Transform::Auth(x),
                    _       => IkeV2Transform::Unknown(r.transform_type,r.transform_id),
                }
            },
            Some(IkeTransformType::DiffieHellmanGroup) => {
                match IkeTransformDHType::from_u16(r.transform_id) {
                    Some(x) => IkeV2Transform::DH(x),
                    _       => IkeV2Transform::Unknown(r.transform_type,r.transform_id),
                }
            },
            Some(IkeTransformType::ExtendedSequenceNumbers) => {
                match IkeTransformESNType::from_u16(r.transform_id) {
                    Some(x) => IkeV2Transform::ESN(x),
                    _       => IkeV2Transform::Unknown(r.transform_type,r.transform_id),
                }
            },
            _ => IkeV2Transform::Unknown(r.transform_type,r.transform_id)
        }
    }
}

impl<'a> From<IkeV2RawTransform<'a>> for IkeV2Transform {
    fn from(r: IkeV2RawTransform) -> IkeV2Transform {
        (&r).into()
    }
}

