# ipsec-parser

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE-MIT)
[![Apache License 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](./LICENSE-APACHE)
[![Build Status](https://travis-ci.org/rusticata/ipsec-parser.svg?branch=master)](https://travis-ci.org/rusticata/ipsec-parser)

## Overview

ipsec-parser is a parser for the IPsec protocols: IKEv2, and reading the envelope of ESP encapsulated messages.

This parser provides the base functions to read and analyze messages, but does not handle the interpretation of messages.

It cannot serialize messages, though this may be added later using the
[cookie-factory](https://crates.io/cookie-factory) crate.

For details and examples, see the [documentation](https://docs.rs/ipsec-parser/)

## Changelog

Release 0.3.0

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
