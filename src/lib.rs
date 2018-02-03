//! IKEv2 parser
//! An IKEv2 (RFC7296) parser, implemented with the [nom](https://github.com/Geal/nom)
//! parser combinator framework.
//!
//! The code is available on [Github](https://github.com/rusticata/ipsec-parser)
//! and is part of the [Rusticata](https://github.com/rusticata) project.
//!
//!
//! ```rust,no_run
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
//!         IResult::Done(rem, ref hdr) => {
//!             match parse_ikev2_payload_list(rem,hdr.next_payload) {
//!                 IResult::Done(_, Ok(ref p)) => {
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

#[macro_use]
extern crate enum_primitive;

#[macro_use]
extern crate rusticata_macros;

#[macro_use]
extern crate nom;

mod ikev2;
pub use ikev2::*;
mod ikev2_notify;
pub use ikev2_notify::*;
mod ikev2_transforms;
pub use ikev2_transforms::*;

mod ikev2_parser;
pub use ikev2_parser::*;

mod ikev2_debug;
pub use ikev2_debug::*;
