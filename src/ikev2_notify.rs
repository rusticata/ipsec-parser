enum_from_primitive! {
/// Defined in [RFC7296] section 3.10.1
/// See also http://www.iana.org/assignments/ikev2-parameters/ikev2-parameters.xhtml
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
