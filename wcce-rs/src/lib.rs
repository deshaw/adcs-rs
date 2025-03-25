#![doc = include_str!("../README.md")]

/// CMS certificate request format, as described in [section 2.2.2.6.2 of
/// MS-WCCE][1].
///
/// > Clients use CMS structures, as specified in [RFC3852][2], to submit
/// > requests to a CA.
///
/// [1]: <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/cef19a68-35af-4727-9bd8-c7126a76e29f>
/// [2]: <https://www.rfc-editor.org/info/rfc3852>
pub mod cms;

/// PKCS #10 certificate request format, as described in [section 2.2.2.6.1 of
/// MS-WCCE][1].
///
/// > Clients use PKCS #10 structures, as specified in [RFC2986][2], to submit
/// > a certificate request to a CA. A PKCS #10 request can be used by itself
/// > or encapsulated within a CMC (as specified in [RFC2797][3]) or a CMS (as
/// > specified in [RFC3852][4]) request.
///
/// [1]: <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/ab1f8f91-b079-4676-bd50-61952bfb011d>
/// [2]: <https://www.rfc-editor.org/info/rfc2986>
/// [3]: <https://www.rfc-editor.org/info/rfc2797>
/// [4]: <https://www.rfc-editor.org/info/rfc3852>
pub mod pkcs10;

/// Certificate extensions specific to MS-WCCE.
pub mod extensions;

/// Certificate request attributes specific to MS-WCCE.
pub mod attributes;

/// Interface for signing certificate requests.
pub mod signing;
