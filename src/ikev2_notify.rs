use rusticata_macros::newtype_enum;

/// Notify Message Type
///
/// Notification information can be error messages specifying why an SA
/// could not be established.  It can also be status data that a process
/// managing an SA database wishes to communicate with a peer process.
///
/// The table below lists the notification messages and their
/// corresponding values.  The number of different error statuses was
/// greatly reduced from IKEv1 both for simplification and to avoid
/// giving configuration information to probers.
///
/// Types in the range 0 - 16383 are intended for reporting errors.  An
/// implementation receiving a Notify payload with one of these types
/// that it does not recognize in a response MUST assume that the
/// corresponding request has failed entirely.  Unrecognized error types
/// in a request and status types in a request or response MUST be
/// ignored, and they should be logged.
///
/// Notify payloads with status types MAY be added to any message and
/// MUST be ignored if not recognized.  They are intended to indicate
/// capabilities, and as part of SA negotiation, are used to negotiate
/// non-cryptographic parameters.
///
/// Defined in [RFC7296](https://tools.ietf.org/html/rfc7296) section 3.10.1
///
/// Extensions:
///
/// - [RFC4555](https://tools.ietf.org/html/rfc4555) IKEv2 Mobility and Multihoming Protocol (MOBIKE)
/// - [RFC4739](https://tools.ietf.org/html/rfc4739) Multiple Authentication Exchanges in the Internet Key Exchange (IKEv2) Protocol
/// - [RFC5685](https://tools.ietf.org/html/rfc5685) Redirect Mechanism for the Internet Key Exchange Protocol Version 2 (IKEv2)
/// - [RFC5723](https://tools.ietf.org/html/rfc5723) Internet Key Exchange Protocol Version 2 (IKEv2) Session Resumption
/// - [RFC7427](https://tools.ietf.org/html/rfc7427) Signature Authentication in the Internet Key Exchange Version 2 (IKEv2)
///
/// See also [IKEV2IANA](https://www.iana.org/assignments/ikev2-parameters/ikev2-parameters.xhtml) for the latest values.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct NotifyType(pub u16);

newtype_enum! {
impl debug NotifyType {
    // error types
    UNSUPPORTED_CRITICAL_PAYLOAD  = 1,
    INVALID_IKE_SPI               = 4,
    INVALID_MAJOR_VERSION         = 5,
    INVALID_SYNTAX                = 7,
    INVALID_MESSAGE_ID            = 9,
    INVALID_SPI                   = 11,
    NO_PROPOSAL_CHOSEN            = 14,
    INVALID_KE_PAYLOAD            = 17,
    AUTHENTICATION_FAILED         = 24,
    SINGLE_PAIR_REQUIRED          = 34,
    NO_ADDITIONAL_SAS             = 35,
    INTERNAL_ADDRESS_FAILURE      = 36,
    FAILED_CP_REQUIRED            = 37,
    TS_UNACCEPTABLE               = 38,
    INVALID_SELECTORS             = 39,
    TEMPORARY_FAILURE             = 43,
    CHILD_SA_NOT_FOUND            = 44,
    // status types
    INITIAL_CONTACT               = 16384,
    SET_WINDOW_SIZE               = 16385,
    ADDITIONAL_TS_POSSIBLE        = 16386,
    IPCOMP_SUPPORTED              = 16387,
    NAT_DETECTION_SOURCE_IP       = 16388,
    NAT_DETECTION_DESTINATION_IP  = 16389,
    COOKIE                        = 16390,
    USE_TRANSPORT_MODE            = 16391,
    HTTP_CERT_LOOKUP_SUPPORTED    = 16392,
    REKEY_SA                      = 16393,
    ESP_TFC_PADDING_NOT_SUPPORTED = 16394,
    NON_FIRST_FRAGMENTS_ALSO      = 16395,
    //
    MULTIPLE_AUTH_SUPPORTED       = 16404,
    ANOTHER_AUTH_FOLLOWS          = 16405,
    REDIRECT_SUPPORTED            = 16406,
    //
    IKEV2_FRAGMENTATION_SUPPORTED = 16430,
    SIGNATURE_HASH_ALGORITHMS     = 16431,
}
}

impl NotifyType {
    pub fn is_error(self) -> bool {
        self.0 < 16384
    }
    pub fn is_status(self) -> bool {
        self.0 > 16384
    }
}
