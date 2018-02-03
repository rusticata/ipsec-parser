use std::fmt;

use enum_primitive::FromPrimitive;

use rusticata_macros::debug::HexSlice;

use ikev2::*;
use ikev2_transforms::*;

// ------------------------- ikev2_transforms.rs ------------------------------
//
impl<'a> fmt::Debug for IkeV2RawTransform<'a> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        let (tf_type, tf_id) = match self.transform_type {
            IkeTransformType::EncryptionAlgorithm => {
                let id = match IkeTransformEncType::from_u16(self.transform_id) {
                    Some(v) => format!("{:?}", v),
                    _       => format!("<Unknown encryption {}>", self.transform_id),
                };
                ("EncryptionAlgorithm".to_string(),id)
            },
            IkeTransformType::PseudoRandomFunction => {
                let id = match IkeTransformPRFType::from_u16(self.transform_id) {
                    Some(v) => format!("{:?}", v),
                    _       => format!("<Unknown PRF {}>", self.transform_id),
                };
                ("PseudoRandomFunction".to_string(),id)
            },
            IkeTransformType::IntegrityAlgorithm => {
                let id = match IkeTransformAuthType::from_u16(self.transform_id) {
                    Some(v) => format!("{:?}", v),
                    _       => format!("<Unknown Auth {}>", self.transform_id),
                };
                ("IntegrityAlgorithm".to_string(),id)
            },
            IkeTransformType::DiffieHellmanGroup => {
                let id = match IkeTransformDHType::from_u16(self.transform_id) {
                    Some(v) => format!("{:?}", v),
                    _       => format!("<Unknown DH group {}>", self.transform_id),
                };
                ("DiffieHellmanGroup".to_string(),id)
            },
            IkeTransformType::ExtendedSequenceNumbers => {
                let id = match IkeTransformESNType::from_u16(self.transform_id) {
                    Some(v) => format!("{:?}", v),
                    _       => format!("<Unknown ESN value {}>", self.transform_id),
                };
                ("ExtendedSequenceNumbers".to_string(),id)
            },
            _    => (format!("<Unknown transform type {}>", self.transform_type.0),"".to_string()),
        };
        fmt.debug_struct("IkeV2RawTransform")
            .field("last", &self.last)
            .field("reserved1", &self.reserved1)
            .field("transform_length", &self.transform_length)
            .field("transform_type", &tf_type)
            .field("reserved2", &self.reserved2)
            .field("transform_id", &tf_id)
            .field("attributes", &self.attributes)
            .finish()
    }
}

// ------------------------- ikev2.rs ------------------------------

impl<'a> fmt::Debug for NoncePayload<'a> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.debug_struct("NoncePayload")
            .field("nonce_data", &HexSlice{d:self.nonce_data})
            .finish()
    }
}

impl<'a> fmt::Debug for NotifyPayload<'a> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.debug_struct("NotifyPayload")
            .field("protocol_id", &self.protocol_id)
            .field("spi_size", &self.spi_size)
            .field("notify_type", &self.notify_type)
            .field("spi", &self.spi)
            .field("notify_data", &self.notify_data.map(|o|{HexSlice{d:o}}))
            .finish()
    }
}
