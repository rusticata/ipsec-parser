#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate ipsec_parser;

fuzz_target!(|data: &[u8]| {
    // fuzzed code goes here
    if data.len() > 0 {
        let _ = ipsec_parser::parse_ikev2_payload_list(&data[1..],data[0]);
    }
});
