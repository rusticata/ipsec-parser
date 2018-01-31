#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate ipsec_parser;

fuzz_target!(|data: &[u8]| {
    // fuzzed code goes here
    let _ = ipsec_parser::parse_ikev2_payload_sa(data,0);
});
