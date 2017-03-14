use std::fmt;

use enum_primitive::FromPrimitive;

use ikev2::*;

// ------------------------- ikev2.rs ------------------------------
//
impl<'a> fmt::Debug for IkeV2Transform<'a> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        let (tf_type, tf_id) = match IkeTransformType::from_u8(self.transform_type) {
            Some(IkeTransformType::EncryptionAlgorithm) => {
                let id = match IkeTransformEncType::from_u16(self.transform_id) {
                    Some(v) => format!("{:?}", v),
                    _       => format!("<Unknown encryption {}>", self.transform_id),
                };
                ("EncryptionAlgorithm".to_string(),id)
            },
            Some(IkeTransformType::PseudoRandomFunction) => {
                let id = match IkeTransformPRFType::from_u16(self.transform_id) {
                    Some(v) => format!("{:?}", v),
                    _       => format!("<Unknown PRF {}>", self.transform_id),
                };
                ("PseudoRandomFunction".to_string(),id)
            },
            Some(IkeTransformType::IntegrityAlgorithm) => {
                let id = match IkeTransformAuthType::from_u16(self.transform_id) {
                    Some(v) => format!("{:?}", v),
                    _       => format!("<Unknown Auth {}>", self.transform_id),
                };
                ("IntegrityAlgorithm".to_string(),id)
            },
            Some(IkeTransformType::DiffieHellmanGroup) => {
                let id = match IkeTransformDHType::from_u16(self.transform_id) {
                    Some(v) => format!("{:?}", v),
                    _       => format!("<Unknown DH group {}>", self.transform_id),
                };
                ("DiffieHellmanGroup".to_string(),id)
            },
            Some(IkeTransformType::ExtendedSequenceNumbers) => {
                let id = match IkeTransformESNType::from_u16(self.transform_id) {
                    Some(v) => format!("{:?}", v),
                    _       => format!("<Unknown ESN value {}>", self.transform_id),
                };
                ("ExtendedSequenceNumbers".to_string(),id)
            },
            None    => (format!("<Unknown transform type {}>", self.transform_type),"".to_string()),
        };
        fmt.debug_struct("IkeV2Transform")
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
