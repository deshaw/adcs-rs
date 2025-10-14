#![allow(clippy::module_name_repetitions)]

use std::{borrow::Cow, io::BufRead, num::ParseIntError, str::FromStr};

use quick_xml::DeError;
use serde::{Deserialize, Serialize};

use crate::common::{ActionType, ActivityId, BinarySecurityToken, Header, RequestId, TokenType};

/// Represents a response in the WS-Trust X.509v3 Token Enrollment Extensions
/// (WSTEP) protocol.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct WstepResponse<'a> {
    /// Contains the SOAP envelope response elements for a WSTEP request.
    pub envelope: ResponseEnvelope<'a>,
}

impl<'a> WstepResponse<'a> {
    /// Creates a new [`WstepResponse`] with the given header and body.
    #[must_use]
    pub fn new(header: Header<'a>, body: ResponseBody<'a>) -> Self {
        Self {
            envelope: ResponseEnvelope::new(header, body),
        }
    }

    /// Creates a new [`WstepResponse`] for an issued X.509v3 certificate.
    ///
    /// # Parameters
    ///
    /// * `activity_id` - Identifies the activity associated with this response.
    /// * `relates_to` - Relates this response to a previous request.
    /// * `request_id` - The identifier of the original certificate request.
    /// * `issuing_ca` - The binary security token of the issuing Certificate Authority.
    /// * `issued_certificate` - The binary security token of the issued certificate.
    #[must_use]
    pub fn new_issued_x509v3(
        activity_id: ActivityId<'a>,
        relates_to: &'a str,
        request_id: &'a str,
        issuing_ca: BinarySecurityToken<'a>,
        issued_certificate: BinarySecurityToken<'a>,
    ) -> Self {
        Self::new(
            Header::new_response_header(
                ActionType::RequestSecurityTokenResponseCollection,
                activity_id,
                relates_to,
            ),
            ResponseBody {
                value: ResponseOutcome::Success(RequestSecurityTokenResponseCollection::new(
                    RequestSecurityTokenResponse::new_issued_x509v3(
                        request_id,
                        issuing_ca,
                        issued_certificate,
                    ),
                )),
            },
        )
    }

    /// Creates a new [`WstepResponse`] for a key exchange token.
    ///
    /// # Parameters
    ///
    /// * `activity_id` - The activity associated with this response.
    /// * `relates_to` - Relates this response to a previous request.
    /// * `key_exchange_token` - The binary security token for key exchange.
    #[must_use]
    pub fn new_key_exchange_token(
        activity_id: ActivityId<'a>,
        relates_to: &'a str,
        key_exchange_token: BinarySecurityToken<'a>,
    ) -> Self {
        Self::new(
            Header::new_response_header(ActionType::KeyExchangeTokenFinal, activity_id, relates_to),
            ResponseBody {
                value: ResponseOutcome::Success(RequestSecurityTokenResponseCollection::new(
                    RequestSecurityTokenResponse::new_key_exchange_token(key_exchange_token),
                )),
            },
        )
    }

    /// Creates a new [`WstepResponse`] for a fault condition.
    ///
    /// # Parameters
    ///
    /// * `fault_type` - The type of fault that occurred.
    /// * `activity_id` - The activity associated with this response.
    /// * `relates_to` - Relates this response to a previous request.
    /// * `fault` - The fault details.
    #[must_use]
    pub fn new_fault(
        fault_type: FaultType,
        activity_id: ActivityId<'a>,
        relates_to: &'a str,
        fault: Fault<'a>,
    ) -> Self {
        Self::new(
            Header::new_response_header(ActionType::from(fault_type), activity_id, relates_to),
            ResponseBody {
                value: ResponseOutcome::Fault(fault),
            },
        )
    }

    /// Creates a new [`WstepResponse`] from a SOAP XML string.
    ///
    /// # Errors
    ///
    /// Returns a [`WstepResponseError`] if parsing fails.
    pub fn new_from_soap_xml_str(xml: &str) -> Result<Self, WstepResponseError> {
        let envelope = quick_xml::de::from_str(xml)?;
        Ok(Self { envelope })
    }

    /// Creates a new [`WstepResponse`] from a SOAP XML reader.
    ///
    /// # Errors
    ///
    /// Returns a [`WstepResponseError`] if parsing fails.
    pub fn new_from_soap_xml_reader(reader: impl BufRead) -> Result<Self, WstepResponseError> {
        let envelope = quick_xml::de::from_reader(reader)?;
        Ok(Self { envelope })
    }

    /// Returns the requested token collection or fault from the response.
    ///
    /// # Returns
    ///
    /// [`RequestSecurityTokenResponseCollection`] if the response contains a
    /// successful token.
    ///
    /// # Errors
    ///
    /// [`Fault`] if the response contains a fault.
    pub const fn requested_token_collection(
        &self,
    ) -> Result<&RequestSecurityTokenResponseCollection<'_>, &Fault<'_>> {
        match &self.envelope.body.value {
            ResponseOutcome::Success(collection) => Ok(collection),
            ResponseOutcome::Fault(fault) => Err(fault),
        }
    }
}

/// Defines the different types of SOAP faults in the MS-WSTEP protocol.
///
/// In the MS-WSTEP protocol, the STS can respond with different types of
/// faults depending on the error condition. These fault types determine
/// the appropriate Action header for the fault response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaultType {
    /// A fault from the WCF dispatcher component.
    DispatcherFault,
    /// A fault with detailed error information.
    DetailFault,
    /// A standard SOAP fault.
    SoapFault,
}

impl From<FaultType> for ActionType {
    fn from(value: FaultType) -> Self {
        match value {
            FaultType::DispatcherFault => Self::Fault,
            FaultType::DetailFault => Self::FaultDetail,
            FaultType::SoapFault => Self::SoapFault,
        }
    }
}

/// Error type for WSTEP response parsing failures.
///
/// Wraps underlying errors that can occur when parsing a SOAP XML response
/// into a structured [`WstepResponse`] object.
#[derive(Debug, Clone)]
pub enum WstepResponseError {
    /// Errors that occur during XML parsing.
    Parse(DeError),
}

impl From<DeError> for WstepResponseError {
    fn from(value: DeError) -> Self {
        Self::Parse(value)
    }
}

impl std::fmt::Display for WstepResponseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Parse(error) => write!(f, "parse error: {error}"),
        }
    }
}

impl std::error::Error for WstepResponseError {}

/// The SOAP envelope for a WSTEP response.
///
/// This structure represents the complete SOAP envelope for a WSTEP response,
/// including the header and body sections as defined in the MS-WSTEP protocol.
#[derive(Debug, Deserialize, PartialEq, Eq, Clone)]
#[serde(rename = "s:Envelope")]
pub struct ResponseEnvelope<'a> {
    /// The XML namespace for SOAP.
    #[serde(rename = "@xmlns:s")]
    pub xmlns_s: Cow<'a, str>,

    /// The XML namespace for WS-Addressing.
    #[serde(rename = "@xmlns:a")]
    pub xmlns_a: Cow<'a, str>,

    /// The SOAP header containing addressing and message metadata.
    #[serde(rename = "s:Header")]
    #[serde(alias = "Header")]
    pub header: Header<'a>,

    /// The SOAP body containing the actual response payload.
    #[serde(rename = "Body")]
    pub body: ResponseBody<'a>,
}

impl<'a> ResponseEnvelope<'a> {
    /// The XML namespace for SOAP.
    const XMLNS_S: &'static str = "http://www.w3.org/2003/05/soap-envelope";

    /// The XML namespace for WS-Addressing.
    const XMLNS_A: &'static str = "http://www.w3.org/2005/08/addressing";

    /// Creates a new response envelope with the given header and body.
    ///
    /// Constructs a complete SOAP envelope with the appropriate namespaces
    /// and the specified header and body components.
    #[must_use]
    pub fn new(header: Header<'a>, body: ResponseBody<'a>) -> Self {
        Self {
            xmlns_s: Self::XMLNS_S.into(),
            xmlns_a: Self::XMLNS_A.into(),
            header,
            body,
        }
    }
}

/// The body section of a WSTEP SOAP response.
///
/// Contains the payload of the WSTEP response, either a successful response
/// containing a security token or a fault.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
pub struct ResponseBody<'a> {
    /// The value of the response, either a success or a fault.
    #[serde(rename = "$value")]
    pub value: ResponseOutcome<'a>,
}

/// Represents the two possible outcomes of a WSTEP request.
///
/// A WSTEP response can either contain a successful result with the
/// requested token, or a fault indicating an error condition.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
#[serde(rename_all = "PascalCase")]
#[allow(clippy::large_enum_variant)]
pub enum ResponseOutcome<'a> {
    /// A successful response containing the requested security token.
    #[serde(rename = "RequestSecurityTokenResponseCollection")]
    Success(RequestSecurityTokenResponseCollection<'a>),

    /// A fault response indicating an error condition.
    #[serde(rename = "Fault")]
    Fault(Fault<'a>),
}

/// Collection of response tokens for a WSTEP request.
///
/// This structure encapsulates one or more security token responses
/// as defined in the WS-Trust specification.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
#[serde(rename = "RequestSecurityTokenResponseCollection")]
pub struct RequestSecurityTokenResponseCollection<'a> {
    /// The XML namespace for WS-Trust.
    #[serde(rename = "@xmlns")]
    pub xmlns: Cow<'a, str>,

    /// The security token response.
    #[serde(rename = "RequestSecurityTokenResponse")]
    pub request_security_token_response: RequestSecurityTokenResponse<'a>,
}

impl<'a> RequestSecurityTokenResponseCollection<'a> {
    /// The XML namespace for WS-Trust.
    const XMLNS: &'a str = "http://docs.oasis-open.org/ws-sx/ws-trust/200512";

    /// Creates a new token response collection with the given response.
    ///
    /// Constructs a collection containing a single security token response.
    #[must_use]
    pub fn new(request_security_token_response: RequestSecurityTokenResponse<'a>) -> Self {
        Self {
            xmlns: Self::XMLNS.into(),
            request_security_token_response,
        }
    }
}
/// Individual security token response within a WSTEP response.
///
/// Contains the details of a specific security token response, including
/// the token itself and associated metadata.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct RequestSecurityTokenResponse<'a> {
    /// The security token that was requested.
    pub requested_security_token: RequestedSecurityToken<'a>,

    /// The type of token that was issued.
    pub token_type: TokenType<'a>,

    /// Optional binary security token, typically the issuing CA certificate.
    pub binary_security_token: Option<BinarySecurityToken<'a>>,

    /// Optional message describing the disposition of the request.
    pub disposition_message: Option<DispositionMessage<'a>>,

    /// Optional identifier for the request that this response pertains to.
    #[serde(rename = "RequestID")]
    pub request_id: Option<RequestId<'a>>,
}

impl<'a> RequestSecurityTokenResponse<'a> {
    /// Creates a new response for an issued X.509v3 certificate.
    ///
    /// # Parameters
    /// * `request_id` - The identifier of the original certificate request
    /// * `issuing_ca` - The certificate of the issuing CA
    /// * `issued_certificate` - The issued certificate
    #[must_use]
    pub fn new_issued_x509v3(
        request_id: &'a str,
        issuing_ca: BinarySecurityToken<'a>,
        issued_certificate: BinarySecurityToken<'a>,
    ) -> Self {
        Self {
            requested_security_token: RequestedSecurityToken::BinarySecurityToken {
                binary_security_token: issued_certificate,
            },
            token_type: TokenType::x509v3(),
            binary_security_token: Some(issuing_ca),
            disposition_message: Some(DispositionMessage::issued()),
            request_id: Some(RequestId::new_with_id(request_id)),
        }
    }

    /// Creates a new response for a key exchange token.
    ///
    /// # Parameters
    /// * `key_exchange_token` - The key exchange token
    #[must_use]
    pub fn new_key_exchange_token(key_exchange_token: BinarySecurityToken<'a>) -> Self {
        Self {
            requested_security_token: RequestedSecurityToken::KeyExchangeToken {
                key_exchange_token: KeyExchangeToken {
                    binary_security_token: key_exchange_token,
                },
            },
            token_type: TokenType::x509v3(),
            binary_security_token: None,
            disposition_message: None,
            request_id: None,
        }
    }
}

/// A message describing the disposition of a certificate request.
///
/// In MS-WSTEP responses, a disposition message indicates the status
/// of the certificate request, such as "Issued", "Pending", etc.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
pub struct DispositionMessage<'a> {
    /// The language of the message.
    #[serde(rename = "@lang")]
    pub lang: Cow<'a, str>,

    /// The XML namespace for the message.
    #[serde(rename = "@xmlns")]
    pub xmlns: Cow<'a, str>,

    /// The actual disposition message text.
    #[serde(rename = "$text")]
    pub value: Cow<'a, str>,
}

impl DispositionMessage<'_> {
    /// The standard language code for English (US).
    const LANG: &'static str = "en-US";

    /// The XML namespace for MS-WSTEP enrollment.
    const XMLNS: &'static str = "http://schemas.microsoft.com/windows/pki/2009/01/enrollment";

    /// The standard message text for issued certificates.
    const MSG_ISSUED: &'static str = "Issued";

    /// Creates a new disposition message indicating the certificate was
    /// issued.
    ///
    /// This is a convenience method for creating the standard "Issued" message
    /// used when a certificate has been successfully issued.
    #[must_use]
    pub fn issued() -> Self {
        Self {
            lang: Self::LANG.into(),
            xmlns: Self::XMLNS.into(),
            value: Self::MSG_ISSUED.into(),
        }
    }
}

/// The security token returned in a WSTEP response.
///
/// This enum represents the different types of security tokens that
/// can be returned in a WSTEP response, such as a certificate or
/// a key exchange token.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
#[serde(untagged)]
pub enum RequestedSecurityToken<'a> {
    /// A binary security token, typically an X.509v3 certificate.
    #[serde(rename_all = "PascalCase")]
    BinarySecurityToken {
        /// The binary security token containing the certificate.
        binary_security_token: BinarySecurityToken<'a>,
    },

    /// A key exchange token used for secure key transport.
    #[serde(rename_all = "PascalCase")]
    KeyExchangeToken {
        /// The key exchange token.
        key_exchange_token: KeyExchangeToken<'a>,
    },
}

impl<'a> RequestedSecurityToken<'a> {
    /// Return the value of the requested security token.
    ///
    /// This method provides access to the underlying binary security token value
    /// regardless of whether this is a direct binary security token or one
    /// contained within a key exchange token.
    #[must_use]
    pub const fn binary_security_token_value(&self) -> &Cow<'a, str> {
        match self {
            RequestedSecurityToken::BinarySecurityToken {
                binary_security_token,
            } => &binary_security_token.value,
            RequestedSecurityToken::KeyExchangeToken { key_exchange_token } => {
                &key_exchange_token.binary_security_token.value
            }
        }
    }
}

impl std::fmt::Display for RequestedSecurityToken<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let bst = self.binary_security_token_value();
        write!(f, "{bst}")
    }
}

/// A key exchange token containing a certificate for secure key transport.
///
/// In MS-WSTEP, a key exchange token contains a certificate that can be
/// used by the client to encrypt private keys when submitting certificate
/// requests.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct KeyExchangeToken<'a> {
    /// The binary security token containing the key exchange certificate.
    pub binary_security_token: BinarySecurityToken<'a>,
}

/// A SOAP fault response in the MS-WSTEP protocol.
///
/// When an error occurs during request processing, the STS responds with
/// a SOAP fault containing details about the error condition.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Fault<'a> {
    /// The fault code indicating the general category of the error.
    #[serde(rename = "s:Code")]
    #[serde(alias = "Code")]
    pub code: FaultCode<'a>,

    /// The human-readable reason for the fault.
    #[serde(rename = "s:Reason")]
    #[serde(alias = "Reason")]
    pub reason: FaultReason<'a>,

    /// Optional detailed information about the fault.
    #[serde(rename = "s:Detail", skip_serializing_if = "Option::is_none")]
    #[serde(alias = "Detail")]
    pub detail: Option<FaultDetail<'a>>,
}

impl std::fmt::Display for Fault<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for Fault<'_> {}

/// The code section of a SOAP fault.
///
/// Contains the standardized code that identifies the fault category,
/// as well as an optional subcode for more specific error information.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct FaultCode<'a> {
    /// The primary fault code value.
    #[serde(rename = "s:Value")]
    #[serde(alias = "Value")]
    pub value: FaultCodeValue<'a>,

    /// Optional subcode providing more specific error information.
    #[serde(rename = "s:Subcode", skip_serializing_if = "Option::is_none")]
    #[serde(alias = "Subcode")]
    pub subcode: Option<FaultSubcode<'a>>,
}

/// The value of a fault code.
///
/// Contains the string representation of the fault code, such as
/// `s:Receiver` or `s:Sender`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct FaultCodeValue<'a> {
    /// The text value of the fault code.
    #[serde(rename = "$text")]
    pub value: Cow<'a, str>,
}

/// A subcode within a fault code providing more specific error information.
///
/// SOAP faults can include sub-codes to provide more detailed error
/// categorization beyond the primary fault code.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct FaultSubcode<'a> {
    /// The value of the subcode.
    #[serde(rename = "s:Value")]
    #[serde(alias = "Value")]
    pub value: FaultSubcodeValue<'a>,
}

/// The value of a fault subcode.
///
/// Contains the string representation of the fault subcode and
/// its associated namespace.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct FaultSubcodeValue<'a> {
    /// The XML namespace for the subcode.
    #[serde(rename = "@xmlns:a", skip_serializing_if = "Option::is_none")]
    pub xmlns_a: Option<Cow<'a, str>>,

    /// The text value of the subcode.
    #[serde(rename = "$text")]
    pub value: Cow<'a, str>,
}

impl<'a> FaultSubcodeValue<'a> {
    /// The XML namespace for WCF dispatcher faults.
    const XMLNS_A: &'static str =
        "http://schemas.microsoft.com/net/2005/12/windowscommunicationfoundation/dispatcher";

    /// Creates a new fault subcode value with the specified text.
    ///
    /// # Parameters
    /// * `value` - The text of the fault subcode
    #[must_use]
    pub fn new(value: &'a str) -> Self {
        Self {
            xmlns_a: Some(Self::XMLNS_A.into()),
            value: value.into(),
        }
    }
}

/// The reason section of a SOAP fault.
///
/// Contains a human-readable explanation of the fault that
/// can be presented to users or logged for troubleshooting.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct FaultReason<'a> {
    /// The text of the fault reason.
    #[serde(rename = "s:Text")]
    #[serde(alias = "Text")]
    pub text: FaultReasonText<'a>,
}

/// The text content of a fault reason.
///
/// Contains the localized text explaining the fault reason,
/// along with a language identifier.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct FaultReasonText<'a> {
    /// The language of the text.
    #[serde(rename = "@lang")]
    pub lang: Cow<'a, str>,

    /// The actual text of the reason.
    #[serde(rename = "$text", skip_serializing_if = "Option::is_none")]
    pub value: Option<Cow<'a, str>>,
}

impl<'a> FaultReasonText<'a> {
    /// The standard language code for English (US).
    const LANG_EN_US: &'static str = "en-US";

    /// Creates a new fault reason text with the specified value.
    ///
    /// # Parameters
    /// - `value` - The text explaining the fault reason
    #[must_use]
    pub fn new(value: Option<&'a str>) -> Self {
        Self {
            lang: Self::LANG_EN_US.into(),
            value: value.map(Into::into),
        }
    }
}

/// Detailed information about a certificate enrollment fault.
///
/// When a certificate enrollment operation fails, this structure
/// provides additional details about the error.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct FaultDetail<'a> {
    /// The certificate enrollment-specific detail information.
    #[serde(rename = "CertificateEnrollmentWSDetail")]
    pub certificate_enrollment_ws_detail: CertificateEnrollmentWsDetail<'a>,
}

/// Certificate enrollment-specific fault details.
///
/// Contains detailed information about a certificate enrollment
/// error, including error codes and request information.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CertificateEnrollmentWsDetail<'a> {
    /// The XML namespace for enrollment.
    #[serde(rename = "@xmlns")]
    pub xmlns: Cow<'a, str>,

    /// The XML namespace for XML Schema.
    #[serde(rename = "@xmlns:xsd")]
    pub xmlns_xsd: Cow<'a, str>,

    /// The XML namespace for XML Schema Instance.
    #[serde(rename = "@xmlns:xsi")]
    pub xmlns_xsi: Cow<'a, str>,

    /// The binary response from the certificate authority.
    #[serde(rename = "BinaryResponse")]
    pub binary_response: BinaryResponse<'a>,

    /// The error code indicating the specific error that occurred.
    #[serde(rename = "ErrorCode")]
    pub error_code: ErrorCode,

    /// Indicates whether the request was invalid.
    #[serde(rename = "InvalidRequest")]
    pub invalid_request: InvalidRequest,

    /// The identifier of the request that resulted in this fault.
    #[serde(rename = "RequestID")]
    pub request_id: RequestId<'a>,
}

impl<'a> CertificateEnrollmentWsDetail<'a> {
    /// The XML namespace for MS-WSTEP enrollment.
    const XMLNS: &'static str = "http://schemas.microsoft.com/windows/pki/2009/01/enrollment";

    /// The XML namespace for XML Schema.
    const XMLNS_XSD: &'static str = "http://www.w3.org/2001/XMLSchema";

    /// The XML namespace for XML Schema Instance.
    const XMLNS_XSI: &'static str = "http://www.w3.org/2001/XMLSchema-instance";

    /// Creates new certificate enrollment fault details.
    ///
    /// # Parameters
    /// * `binary_response` - The binary response from the CA
    /// * `error_code` - The specific error code
    /// * `invalid_request` - Indicates whether the request was invalid
    /// * `request_id` - The identifier of the original request
    #[must_use]
    pub fn new(
        binary_response: BinaryResponse<'a>,
        error_code: ErrorCode,
        invalid_request: InvalidRequest,
        request_id: RequestId<'a>,
    ) -> Self {
        Self {
            xmlns: Self::XMLNS.into(),
            xmlns_xsd: Self::XMLNS_XSD.into(),
            xmlns_xsi: Self::XMLNS_XSI.into(),
            binary_response,
            error_code,
            invalid_request,
            request_id,
        }
    }
}

/// Binary response data in a certificate enrollment fault.
///
/// Contains binary data related to the fault, typically an
/// encoded error response from the certificate authority.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BinaryResponse<'a> {
    /// The binary response data.
    #[serde(rename = "$text")]
    pub value: Cow<'a, str>,
}

impl<'a> BinaryResponse<'a> {
    /// Creates a new binary response with the specified value.
    ///
    /// # Parameters
    /// * `value` - The binary response data
    #[must_use]
    pub fn new(value: &'a str) -> Self {
        Self {
            value: value.into(),
        }
    }
}

/// Error codes used in certificate enrollment faults.
///
/// These codes represent specific error conditions that can occur
/// during certificate enrollment, as defined by the MS-WSTEP protocol.
#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
pub enum ErrorCode {
    /// ASN1 unexpected end of data.
    Asn1Eod,
    /// The request contains an invalid renewal certificate attribute.
    BadRenewalCertAttribute,
    /// The request subject name is invalid or too long.
    BadRequestSubject,
    /// The request template version is newer than the supported template
    /// version.
    BadTemplateVersion,
    /// The permissions on this certification authority do not allow the
    /// current user to enroll for certificates.
    EnrollDenied,
    /// The operation is denied. It can only be performed by a certificate
    /// manager that is allowed to manage certificates for the current
    /// requester.
    RestrictedOfficer,
    /// The request contains conflicting template information.
    TemplateConflict,
    /// An error code not yet documented by this library.
    /// Consider opening a pull request to add it!
    Other(u32),
}

impl From<u32> for ErrorCode {
    fn from(code: u32) -> Self {
        match code {
            0x8009_3102 => Self::Asn1Eod,
            0x8009_400E => Self::BadRenewalCertAttribute,
            0x8009_4001 => Self::BadRequestSubject,
            0x8009_4807 => Self::BadTemplateVersion,
            0x8009_4011 => Self::EnrollDenied,
            0x8009_4009 => Self::RestrictedOfficer,
            0x8009_4802 => Self::TemplateConflict,
            unknown_code => Self::Other(unknown_code),
        }
    }
}

impl FromStr for ErrorCode {
    type Err = ErrorCodeParseError;

    /// These codes make the most sense in hex, e.g. `0x8009_4807`.
    /// Microsoft documents the codes this way, and the upper bytes can also be
    /// useful as a broad category.
    /// AD CS, however, returns these codes as i32 strings, e.g. "-2146875385".
    #[allow(clippy::cast_sign_loss)]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self::from(
            i32::from_str(s).map_err(ErrorCodeParseError)? as u32
        ))
    }
}

impl<'de> Deserialize<'de> for ErrorCode {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        (<&str>::deserialize(deserializer)?)
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

/// Error that occurs when parsing an error code string fails.
///
/// This error is returned when a string cannot be parsed into
/// a valid [`ErrorCode`], typically due to an invalid integer format.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrorCodeParseError(ParseIntError);

impl std::fmt::Display for ErrorCodeParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "failed to parse MS-WSTEP Fault ErrorCode: {}", self.0)
    }
}

impl std::error::Error for ErrorCodeParseError {}

impl std::fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Asn1Eod => write!(f, "ASN1 unexpected end of data."),
            Self::BadRenewalCertAttribute => write!(
                f,
                "The request contains an invalid renewal certificate attribute."
            ),
            Self::BadRequestSubject => {
                write!(f, "The request subject name is invalid or too long.")
            }
            Self::BadTemplateVersion => write!(
                f,
                "The request template version is newer than the supported template version."
            ),
            Self::EnrollDenied => write!(
                f,
                "The permissions on this certification authority do not allow the current user to enroll for certificates."
            ),
            Self::RestrictedOfficer => write!(f, "The operation is denied. It can only be performed by a certificate manager that is allowed to manage certificates for the current requester."),
            Self::TemplateConflict => write!(f, "The request contains conflicting template information."),
            Self::Other(code) => write!(f, "Unknown error description for code {code}."),
        }
    }
}

/// Indicates whether a request was invalid.
///
/// In certificate enrollment faults, this flag indicates whether
/// the original request was considered invalid by the server.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct InvalidRequest {
    /// The flag value.
    #[serde(rename = "$text")]
    pub value: bool,
}

impl InvalidRequest {
    /// Creates a new invalid request flag with the specified value.
    ///
    /// # Parameters
    /// * `invalid` - Whether the request was invalid
    #[must_use]
    pub const fn new(invalid: bool) -> Self {
        Self { value: invalid }
    }
}
