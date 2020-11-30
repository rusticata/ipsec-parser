//! # IPsec parsers
//!
//! This crate contains several parsers using for IPsec: IKEv2, and reading the envelope of ESP
//! encapsulated messages.
//! This parser provides the base functions to read and analyze messages, but does not handle the
//! interpretation of messages.
//!
//! ESP is supported, but only to read the envelope of the payload.
//!
//! Encapsulated ESP is supported, to differentiate between IKE and ESP headers.
//!
//! # IKEv2 parser
//!
//! An IKEv2 (RFC7296) parser, implemented with the [nom](https://github.com/Geal/nom)
//! parser combinator framework.
//!
//! The code is available on [Github](https://github.com/rusticata/ipsec-parser)
//! and is part of the [Rusticata](https://github.com/rusticata) project.
//!
//! To parse an IKE packet, first read the header using `parse_ikev2_header`, then use the type
//! from the header to parse the remaining part:
//!
//!
//! ```rust
//! # extern crate nom;
//! # extern crate ipsec_parser;
//! use ipsec_parser::*;
//! use nom::IResult;
//!
//! static IKEV2_INIT_RESP: &'static [u8] = include_bytes!("../assets/ike-sa-init-resp.bin");
//!
//! # fn main() {
//! fn test_ikev2_init_resp() {
//!     let bytes = IKEV2_INIT_RESP;
//!     match parse_ikev2_header(&bytes) {
//!         Ok( (rem, ref hdr) ) => {
//!             match parse_ikev2_payload_list(rem,hdr.next_payload) {
//!                 Ok( (_, Ok(ref p)) ) => {
//!                     // p is a list of payloads
//!                     // first one is always dummy
//!                     assert!(p.len() > 0);
//!                     assert_eq!(p[0].content, IkeV2PayloadContent::Dummy);
//!                     for payload in p {
//!                         match payload.content {
//!                             IkeV2PayloadContent::SA(ref sa) => { /* .. */ },
//!                             _ => ()
//!                         }
//!                     }
//!                 },
//!                 e => { eprintln!("Parsing payload failed: {:?}", e); },
//!             }
//!         },
//!         _ => { eprintln!("Parsing header failed"); },
//!     }
//! }
//! # }
//! ```

#![deny(/*missing_docs,*/
        unstable_features,
        unused_import_braces, unused_qualifications)]
#![forbid(unsafe_code)]

mod error;
mod esp;
mod ikev2;
mod ikev2_debug;
mod ikev2_notify;
mod ikev2_parser;
mod ikev2_transforms;
pub use error::*;
pub use esp::*;
pub use ikev2::*;
pub use ikev2_debug::*;
pub use ikev2_notify::*;
pub use ikev2_parser::*;
pub use ikev2_transforms::*;

// re-export modules
pub use nom;
