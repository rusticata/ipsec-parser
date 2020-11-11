use rusticata_macros::newtype_enum;
use std::convert::From;

/// Transform (cryptographic algorithm) type
///
/// Defined in [RFC7296](https://tools.ietf.org/html/rfc7296) section 3.3.2
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct IkeTransformType(pub u8);

newtype_enum! {
impl debug IkeTransformType {
    EncryptionAlgorithm     = 1,
    PseudoRandomFunction    = 2,
    IntegrityAlgorithm      = 3,
    DiffieHellmanGroup      = 4,
    ExtendedSequenceNumbers = 5,
}
}

/// Encryption values
///
/// Defined in [RFC7296](https://tools.ietf.org/html/rfc7296) section 3.3.2
///
/// See also [IKEV2IANA](https://www.iana.org/assignments/ikev2-parameters/ikev2-parameters.xhtml) for the latest values.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct IkeTransformEncType(pub u16);

newtype_enum! {
impl debug IkeTransformEncType {
    // 0 is reserved
    ENCR_DES_IV64           = 1,
    ENCR_DES                = 2,
    ENCR_3DES               = 3,
    ENCR_RC5                = 4,
    ENCR_IDEA               = 5,
    ENCR_CAST               = 6,
    ENCR_BLOWFISH           = 7,
    ENCR_3IDEA              = 8,
    ENCR_DES_IV32           = 9,
    // 10 is reserved
    ENCR_NULL                = 11,
    ENCR_AES_CBC             = 12,
    ENCR_AES_CTR             = 13,
    ENCR_AES_CCM_8           = 14,
    ENCR_AES_CCM_12          = 15,
    ENCR_AES_CCM_16          = 16,
    // 17 is unassigned
    ENCR_AES_GCM_8           = 18,
    ENCR_AES_GCM_12          = 19,
    ENCR_AES_GCM_16          = 20,
    ENCR_NULL_AUTH_AES_GMAC  = 21,
    // 22 is reserved for IEEE P1619 XTS-AES
    ENCR_CAMELLIA_CBC        = 23,
    ENCR_CAMELLIA_CTR        = 24,
    ENCR_CAMELLIA_CCM_8      = 25,
    ENCR_CAMELLIA_CCM_12     = 26,
    ENCR_CAMELLIA_CCM_16     = 27,
    ENCR_CHACHA20_POLY1305   = 28, // [RFC7634]
}
}

impl IkeTransformEncType {
    pub fn is_aead(self) -> bool {
        matches!(
            self,
            IkeTransformEncType::ENCR_AES_CCM_8
                | IkeTransformEncType::ENCR_AES_CCM_12
                | IkeTransformEncType::ENCR_AES_CCM_16
                | IkeTransformEncType::ENCR_AES_GCM_8
                | IkeTransformEncType::ENCR_AES_GCM_12
                | IkeTransformEncType::ENCR_AES_GCM_16
                | IkeTransformEncType::ENCR_CAMELLIA_CCM_8
                | IkeTransformEncType::ENCR_CAMELLIA_CCM_12
                | IkeTransformEncType::ENCR_CAMELLIA_CCM_16
                | IkeTransformEncType::ENCR_CHACHA20_POLY1305
        )
    }

    pub fn is_unassigned(self) -> bool {
        self.0 >= 23 && self.0 <= 1023
    }
    pub fn is_private_use(self) -> bool {
        self.0 >= 1024
    }
}

/// Pseudo-Random Function values
///
/// Defined in [RFC7296](https://tools.ietf.org/html/rfc7296) section 3.3.2
///
/// See also [IKEV2IANA](https://www.iana.org/assignments/ikev2-parameters/ikev2-parameters.xhtml) for the latest values.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct IkeTransformPRFType(pub u16);

newtype_enum! {
impl debug IkeTransformPRFType {
    PRF_NULL          = 0,
    PRF_HMAC_MD5      = 1,
    PRF_HMAC_SHA1     = 2,
    PRF_HMAC_TIGER    = 3,
    PRF_AES128_XCBC   = 4,
    PRF_HMAC_SHA2_256 = 5,
    PRF_HMAC_SHA2_384 = 6,
    PRF_HMAC_SHA2_512 = 7,
    PRF_AES128_CMAC   = 8,
}
}

impl IkeTransformPRFType {
    pub fn is_unassigned(self) -> bool {
        self.0 >= 9 && self.0 <= 1023
    }
    pub fn is_private_use(self) -> bool {
        self.0 >= 1024
    }
}

/// Authentication / Integrity values
///
/// Defined in [RFC7296](https://tools.ietf.org/html/rfc7296) section 3.3.2
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct IkeTransformAuthType(pub u16);

newtype_enum! {
impl debug IkeTransformAuthType {
    NONE                   = 0,
    AUTH_HMAC_MD5_96       = 1,
    AUTH_HMAC_SHA1_96      = 2,
    AUTH_DES_MAC           = 3,
    AUTH_KPDK_MD5          = 4,
    AUTH_AES_XCBC_96       = 5,
    AUTH_HMAC_MD5_128      = 6,
    AUTH_HMAC_SHA1_160     = 7,
    AUTH_AES_CMAC_96       = 8,
    AUTH_AES_128_GMAC      = 9,
    AUTH_AES_192_GMAC      = 10,
    AUTH_AES_256_GMAC      = 11,
    AUTH_HMAC_SHA2_256_128 = 12,
    AUTH_HMAC_SHA2_384_192 = 13,
    AUTH_HMAC_SHA2_512_256 = 14,
}
}

impl IkeTransformAuthType {
    pub fn is_unassigned(self) -> bool {
        self.0 >= 15 && self.0 <= 1023
    }
    pub fn is_private_use(self) -> bool {
        self.0 >= 1024
    }
}

/// Diffie-Hellman values
///
/// Defined in [RFC7296](https://tools.ietf.org/html/rfc7296) section 3.3.2
///
/// See also [IKEV2IANA](https://www.iana.org/assignments/ikev2-parameters/ikev2-parameters.xhtml) for the latest values.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct IkeTransformDHType(pub u16);

newtype_enum! {
impl debug IkeTransformDHType {
    None            = 0,
    Modp768         = 1,
    Modp1024        = 2,
    Modp1536        = 5,
    Modp2048        = 14,
    Modp3072        = 15,
    Modp4096        = 16,
    Modp6144        = 17,
    Modp8192        = 18,
    Ecp256          = 19,
    Ecp384          = 20,
    Ecp521          = 21,
    Modp1024s160    = 22,
    Modp2048s224    = 23,
    Modp2048s256    = 24,
    Ecp192          = 25,
    Ecp224          = 26,
    BrainpoolP224r1 = 27,
    BrainpoolP256r1 = 28,
    BrainpoolP384r1 = 29,
    BrainpoolP512r1 = 30,
    Curve25519      = 31,
    Curve448        = 32,
}
}

impl IkeTransformDHType {
    pub fn is_unassigned(self) -> bool {
        self.0 >= 15 && self.0 <= 1023
    }
    pub fn is_private_use(self) -> bool {
        self.0 >= 1024
    }
}

/// Extended Sequence Number values
///
/// Defined in [RFC7296](https://tools.ietf.org/html/rfc7296) section 3.3.2
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct IkeTransformESNType(pub u16);

newtype_enum! {
impl debug IkeTransformESNType {
    NoESN = 0,
    ESN   = 1,
}
}

/// Raw representation of a transform (cryptographic algorithm) and parameters
///
/// Use the `From` method to convert it to a [`IkeV2Transform`](enum.IkeV2Transform.html)
///
/// Defined in [RFC7296](https://tools.ietf.org/html/rfc7296) section 3.3
#[derive(Clone, PartialEq)]
pub struct IkeV2RawTransform<'a> {
    pub last: u8,
    pub reserved1: u8,
    pub transform_length: u16,
    pub transform_type: IkeTransformType,
    pub reserved2: u8,
    pub transform_id: u16,
    pub attributes: Option<&'a [u8]>,
}

/// IKEv2 Transform (cryptographic algorithm)
///
/// This structure is a simple representation of a transform, containing only the type (encryption,
/// etc.). To store the parameters, use [`IkeV2RawTransform`](struct.IkeV2RawTransform.html).
///
/// Defined in [RFC7296](https://tools.ietf.org/html/rfc7296) section 3.3
#[derive(Debug, PartialEq)]
pub enum IkeV2Transform {
    Encryption(IkeTransformEncType),
    PRF(IkeTransformPRFType),
    Auth(IkeTransformAuthType),
    DH(IkeTransformDHType),
    ESN(IkeTransformESNType),
    /// Unknown tranform (type,id)
    Unknown(IkeTransformType, u16),
}

impl<'a> From<&'a IkeV2RawTransform<'a>> for IkeV2Transform {
    fn from(r: &IkeV2RawTransform) -> IkeV2Transform {
        match r.transform_type {
            IkeTransformType::EncryptionAlgorithm => {
                IkeV2Transform::Encryption(IkeTransformEncType(r.transform_id))
            }
            IkeTransformType::PseudoRandomFunction => {
                IkeV2Transform::PRF(IkeTransformPRFType(r.transform_id))
            }
            IkeTransformType::IntegrityAlgorithm => {
                IkeV2Transform::Auth(IkeTransformAuthType(r.transform_id))
            }
            IkeTransformType::DiffieHellmanGroup => {
                IkeV2Transform::DH(IkeTransformDHType(r.transform_id))
            }
            IkeTransformType::ExtendedSequenceNumbers => {
                IkeV2Transform::ESN(IkeTransformESNType(r.transform_id))
            }
            _ => IkeV2Transform::Unknown(r.transform_type, r.transform_id),
        }
    }
}

impl<'a> From<IkeV2RawTransform<'a>> for IkeV2Transform {
    fn from(r: IkeV2RawTransform) -> IkeV2Transform {
        (&r).into()
    }
}
