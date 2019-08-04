# ipsec-parser

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE-MIT)
[![Apache License 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](./LICENSE-APACHE)
[![Build Status](https://travis-ci.org/rusticata/ipsec-parser.svg?branch=master)](https://travis-ci.org/rusticata/ipsec-parser)

<!-- cargo-sync-readme start -->

# IPsec parsers

This crate contains several parsers using for IPsec: IKEv2, and reading the envelope of ESP
encapsulated messages.
This parser provides the base functions to read and analyze messages, but does not handle the
interpretation of messages.

ESP is supported, but only to read the envelope of the payload.

Encapsulated ESP is supported, to differentiate between IKE and ESP headers.

# IKEv2 parser

An IKEv2 (RFC7296) parser, implemented with the [nom](https://github.com/Geal/nom)
parser combinator framework.

The code is available on [Github](https://github.com/rusticata/ipsec-parser)
and is part of the [Rusticata](https://github.com/rusticata) project.

To parse an IKE packet, first read the header using `parse_ikev2_header`, then use the type
from the header to parse the remaining part:


```rust
use ipsec_parser::*;
use nom::IResult;

static IKEV2_INIT_RESP: &'static [u8] = include_bytes!("../assets/ike-sa-init-resp.bin");

fn test_ikev2_init_resp() {
    let bytes = IKEV2_INIT_RESP;
    match parse_ikev2_header(&bytes) {
        Ok( (rem, ref hdr) ) => {
            match parse_ikev2_payload_list(rem,hdr.next_payload) {
                Ok( (_, Ok(ref p)) ) => {
                    // p is a list of payloads
                    // first one is always dummy
                    assert!(p.len() > 0);
                    assert_eq!(p[0].content, IkeV2PayloadContent::Dummy);
                    for payload in p {
                        match payload.content {
                            IkeV2PayloadContent::SA(ref sa) => { /* .. */ },
                            _ => ()
                        }
                    }
                },
                e => { eprintln!("Parsing payload failed: {:?}", e); },
            }
        },
        _ => { eprintln!("Parsing header failed"); },
    }
}
```

<!-- cargo-sync-readme end -->

## Changelog

### 0.5.0

- Upgrade to nom 5

### 0.4.1

- o not use glob imports in `use` groups (compatibility with rust 1.24)

### 0.4.0

- Upgrade to nom 4

### 0.3.0

* Add function `parse_ikev2_message` to read header and payload list
* `init_spi` and `resp_spi` fields have been changed from `&[u8]` to `u64`

## Rusticata

This parser is part of the [rusticata](https://github.com/rusticata) project.
The goal of this project is to provide **safe** parsers, that can be used in other projects.

Testing of the parser is done manually, and also using unit tests and
[cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz). Please fill a bugreport if you find any issue.

Feel free to contribute: tests, feedback, doc, suggestions (or code) of new parsers etc. are welcome.

## License

Licensed under either of

 * Apache License, Version 2.0
   ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license
   ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
