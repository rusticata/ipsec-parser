enum_from_primitive! {
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
#[derive(Debug,PartialEq)]
#[repr(u16)]
pub enum Notify {
    UnsupportedCriticalPayload = 1,
    InvalidIkeSpi = 4,
    InvalidMajorVersion = 5,
    InvalidSyntax = 7,
    InvalidMessageId = 9,
    InvalidSpi = 11,
    MoProposalChosen =14,
    InvalidKePayload = 17,
    AuthenticationFailed = 24,
    SinglePairRequired = 34,
    NoAdditionalSas = 35,
    InternetAddressFailure = 36,
    FailedCpRequired = 37,
    TsUnacceptable = 38,
    InvalidSelectors = 39,
    TemporaryFailure = 43,
    ChildSaNotFound = 44,

    InitialContact = 16384,
    SetWindowSize = 16385,
    AdditionalTsPossible = 16386,
    IpcompSupported = 16387,
    NatDetectionSourceIp = 16388,
    NatDetectionDestinationIp = 16389,
    Cookie = 16390,
    UseTransportMode = 16391,
    HttpCertLookupSupported = 16392,
    RekeySa = 16393,
    EspTfcPaddingNotSupported = 16394,
    NonFirstFragmentsAlso = 16395,


    MultipleAuthSupported = 16404,
    AnotherAuthFollows = 16405,
    RedirectSupported = 16406,

    FragmentationSupported = 16430,
    SignatureHashAlgorithms = 16431,
}
}
