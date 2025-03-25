#![allow(clippy::module_name_repetitions)]

use std::{borrow::Cow, str::FromStr};

use serde::Serialize;

use crate::common::{ActionType, BinarySecurityToken, Header, RequestId, TokenType};

/// Represents a WS-Trust X.509v3 Token Enrollment Extensions (WSTEP) request.
///
/// This struct encapsulates the details of a WSTEP request, including the SOAP envelope
/// and its contents as defined in the MS-WSTEP specification.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::module_name_repetitions)]
pub struct WstepRequest<'a> {
    /// Contains the SOAP envelope response elements for a WSTEP request.
    pub request_envelope: RequestEnvelope<'a>,
}

impl<'a> WstepRequest<'a> {
    /// The "anonymous" URI for the WS-Addressing `ReplyTo` field.
    pub const REPLY_TO_ANONYMOUS: &'static str = "http://www.w3.org/2005/08/addressing/anonymous";

    /// The content type for SOAP messages in WSTEP.
    pub const SOAP_CONTENT_TYPE: &'static str = "application/soap+xml; charset=utf-8";

    /// Creates a new [`WstepRequest`] for issuing an X.509v3 certificate.
    ///
    /// This method constructs a request for a new certificate using the PKCS#7 CMS format.
    ///
    /// # Arguments
    ///
    /// * `request_pkcs7_cms_base64` - The base64-encoded PKCS#7 CMS request.
    /// * `message_id` - A unique identifier for the message.
    /// * `to` - The recipient's address.
    ///
    /// # Returns
    ///
    /// A new [`WstepRequest`] instance configured for issuing an X.509v3 certificate.
    #[must_use]
    pub fn new_issue_x509v3(
        request_pkcs7_cms_base64: &'a str,
        message_id: &'a str,
        to: Option<&'a str>,
        reply_to: Option<&'a str>,
    ) -> Self {
        Self {
            request_envelope: RequestEnvelope::new_issue_x509v3(
                Header::new_request_header(
                    ActionType::RequestSecurityToken,
                    message_id,
                    to,
                    reply_to,
                ),
                BinarySecurityToken::new_pkcs7_base64(request_pkcs7_cms_base64),
            ),
        }
    }

    /// Creates a new [`WstepRequest`] for a Key Exchange Token (KET) request.
    ///
    /// This method constructs a request for a Key Exchange Token as defined in the MS-WSTEP specification.
    ///
    /// # Arguments
    ///
    /// * `message_id` - A unique identifier for the message.
    /// * `reply_to` - The address to which the response should be sent.
    ///
    /// # Returns
    ///
    /// A new [`WstepRequest`] instance configured for a Key Exchange Token request.
    #[must_use]
    pub fn new_key_exchange_token(message_id: &'a str, reply_to: &'a str) -> Self {
        Self {
            request_envelope: RequestEnvelope::new_key_exchange_token(message_id, reply_to),
        }
    }

    /// Creates a new [`WstepRequest`] for querying the status of a token.
    ///
    /// This method constructs a request to check the status of a previously submitted certificate request.
    ///
    /// # Arguments
    ///
    /// * `request_id` - The identifier of the original certificate request.
    /// * `message_id` - A unique identifier for this status query message.
    /// * `reply_to` - The address to which the response should be sent.
    ///
    /// # Returns
    ///
    /// A new [`WstepRequest`] instance configured for querying token status.
    #[must_use]
    pub fn new_query_token_status(
        request_id: &'a str,
        message_id: &'a str,
        reply_to: &'a str,
    ) -> Self {
        Self {
            request_envelope: RequestEnvelope::new_query_token_status(
                request_id, message_id, reply_to,
            ),
        }
    }

    /// Serializes the [`WstepRequest`] into a SOAP XML string.
    ///
    /// This method converts the request into a properly formatted SOAP envelope
    /// as required by the MS-WSTEP specification.
    ///
    /// # Returns
    /// A [`Result`] containing the serialized XML string.
    ///
    /// # Errors
    /// Returns a [`WstepRequestSerializationError`] if serialization fails.
    pub fn serialize_request(&self) -> Result<String, WstepRequestSerializationError> {
        quick_xml::se::to_string_with_root("s:Envelope", &self.request_envelope)
            .map_err(WstepRequestSerializationError)
    }
}

/// Error that occurs when serializing a WSTEP request fails.
#[derive(Debug, Clone)]
pub struct WstepRequestSerializationError(quick_xml::SeError);

impl std::fmt::Display for WstepRequestSerializationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "failed to serialize MS-WSTEP request: {0}", self.0)
    }
}

impl std::error::Error for WstepRequestSerializationError {}

/// The SOAP envelope for a WSTEP request.
///
/// This structure represents the complete SOAP envelope for a WSTEP request,
/// including the header and body sections as defined in the MS-WSTEP protocol.
#[derive(Debug, Serialize, PartialEq, Eq, Clone)]
#[serde(rename = "s:Envelope")]
pub struct RequestEnvelope<'a> {
    /// The XML namespace for WS-Addressing.
    #[serde(rename = "@xmlns:a")]
    pub xmlns_a: Cow<'a, str>,

    /// The XML namespace for SOAP.
    #[serde(rename = "@xmlns:s")]
    pub xmlns_s: Cow<'a, str>,

    /// The SOAP header containing addressing and message metadata.
    #[serde(rename = "s:Header")]
    #[serde(alias = "Header")]
    pub header: Header<'a>,

    /// The SOAP body containing the actual request payload.
    #[serde(rename = "s:Body")]
    #[serde(alias = "Body")]
    pub body: RequestBody<'a>,
}

impl<'a> RequestEnvelope<'a> {
    /// The XML namespace for WS-Addressing.
    const XMLNS_A: &'static str = "http://www.w3.org/2005/08/addressing";

    /// The XML namespace for SOAP.
    const XMLNS_S: &'static str = "http://www.w3.org/2003/05/soap-envelope";

    /// Creates a new request envelope for issuing an X.509v3 certificate.
    ///
    /// # Arguments
    ///
    /// * `header` - The SOAP header containing addressing information.
    /// * `binary_security_token` - Token containing the certificate request.
    ///
    /// # Returns
    ///
    /// A new [`RequestEnvelope`] configured for a certificate issuance
    /// request.
    #[must_use]
    pub fn new_issue_x509v3(
        header: Header<'a>,
        binary_security_token: BinarySecurityToken<'a>,
    ) -> Self {
        Self {
            xmlns_a: Self::XMLNS_A.into(),
            xmlns_s: Self::XMLNS_S.into(),
            header,
            body: RequestBody::new_issue_x509v3(binary_security_token),
        }
    }

    /// Creates a new request envelope for a Key Exchange Token request.
    ///
    /// # Arguments
    ///
    /// * `message_id` - A unique identifier for this message.
    /// * `reply_to` - The address to which the response should be sent.
    ///
    /// # Returns
    ///
    /// A new [`RequestEnvelope`] configured for a Key Exchange Token request.
    #[must_use]
    pub fn new_key_exchange_token(message_id: &'a str, reply_to: &'a str) -> Self {
        Self {
            xmlns_a: Self::XMLNS_A.into(),
            xmlns_s: Self::XMLNS_S.into(),
            header: Header::new_request_header(
                ActionType::KeyExchangeToken,
                message_id,
                None,
                Some(reply_to),
            ),
            body: RequestBody::new_key_exchange_token(),
        }
    }

    /// Creates a new request envelope for querying token status.
    ///
    /// # Arguments
    ///
    /// * `request_id` - The identifier of the original certificate request.
    /// * `message_id` - A unique identifier for this message.
    /// * `reply_to` - The address to which the response should be sent.
    ///
    /// # Returns
    ///
    /// A new `RequestEnvelope` configured for querying token status.
    #[must_use]
    pub fn new_query_token_status(
        request_id: &'a str,
        message_id: &'a str,
        reply_to: &'a str,
    ) -> Self {
        Self {
            xmlns_a: Self::XMLNS_A.into(),
            xmlns_s: Self::XMLNS_S.into(),
            header: Header::new_request_header(
                ActionType::RequestSecurityToken,
                message_id,
                None,
                Some(reply_to),
            ),
            body: RequestBody::new_query_token_status(request_id),
        }
    }
}

/// The body section of a WSTEP SOAP request.
///
/// This structure contains the payload of the WSTEP request, primarily
/// the [`RequestSecurityToken`] element that specifies the certificate
/// operation.
#[derive(Debug, Serialize, PartialEq, Eq, Clone)]
pub struct RequestBody<'a> {
    /// The XML namespace for XML Schema Instance.
    #[serde(rename = "@xmlns:xsi")]
    pub xmlns_xsi: Cow<'a, str>,

    /// The XML namespace for XML Schema.
    #[serde(rename = "@xmlns:xsd")]
    pub xmlns_xsd: Cow<'a, str>,

    /// The main request element containing the certificate operation details.
    #[serde(rename = "RequestSecurityToken")]
    pub request_security_token: RequestSecurityToken<'a>,
}

impl<'a> RequestBody<'a> {
    /// The XML namespace for XML Schema Instance.
    const XMLNS_XSI: &'static str = "http://www.w3.org/2001/XMLSchema-instance";

    /// The XML namespace for XML Schema.
    const XMLNS_XSD: &'static str = "http://www.w3.org/2001/XMLSchema";

    /// Creates a new request body for issuing an X.509v3 certificate.
    ///
    /// # Arguments
    ///
    /// * `binary_security_token` - Token containing the certificate request.
    ///
    /// # Returns
    ///
    /// A new `RequestBody` configured for a certificate issuance request.
    #[must_use]
    pub fn new_issue_x509v3(binary_security_token: BinarySecurityToken<'a>) -> Self {
        Self {
            xmlns_xsi: Self::XMLNS_XSI.into(),
            xmlns_xsd: Self::XMLNS_XSD.into(),
            request_security_token: RequestSecurityToken::new_issue_x509v3(binary_security_token),
        }
    }

    /// Creates a new request body for a Key Exchange Token request.
    ///
    /// # Returns
    ///
    /// A new `RequestBody` configured for a Key Exchange Token request.
    #[must_use]
    pub fn new_key_exchange_token() -> Self {
        Self {
            xmlns_xsi: Self::XMLNS_XSI.into(),
            xmlns_xsd: Self::XMLNS_XSD.into(),
            request_security_token: RequestSecurityToken::new_key_exchange_token(),
        }
    }

    /// Creates a new request body for querying token status.
    ///
    /// # Arguments
    ///
    /// * `request_id` - The identifier of the original certificate request.
    ///
    /// # Returns
    ///
    /// A new `RequestBody` configured for querying token status.
    #[must_use]
    pub fn new_query_token_status(request_id: &'a str) -> Self {
        Self {
            xmlns_xsi: Self::XMLNS_XSI.into(),
            xmlns_xsd: Self::XMLNS_XSD.into(),
            request_security_token: RequestSecurityToken::new_query_token_status(request_id),
        }
    }
}

/// A `RequestSecurityToken` as defined by MS-WSTEP.
///
/// MS-WSTEP defines the content model for this element as non-deterministic.
/// Thus, this enumeration represents the intended content model as documented
/// in section 3.1.4.1.3.3 of MS-WSTEP.
#[derive(Debug, Serialize, PartialEq, Eq, Clone)]
pub struct RequestSecurityToken<'a> {
    /// The XML namespace for WS-Trust.
    #[serde(rename = "@xmlns")]
    pub xmlns: Cow<'a, str>,

    /// The type of token being requested, always X.509v3 in WSTEP.
    #[serde(rename = "TokenType")]
    pub token_type: TokenType<'a>,

    /// The type of request being made, e.g. `Issue`, `QueryTokenStatus`, or
    /// `KeyExchangeToken`.
    #[serde(rename = "RequestType")]
    pub request_type: RequestType,

    /// The binary security token containing the certificate request,
    /// if applicable.
    #[serde(
        rename = "BinarySecurityToken",
        skip_serializing_if = "Option::is_none"
    )]
    pub binary_security_token: Option<BinarySecurityToken<'a>>,

    /// Flag indicating this is a Key Exchange Token request, if applicable.
    #[serde(rename = "RequestKET", skip_serializing_if = "Option::is_none")]
    pub request_ket: Option<()>,

    /// The request identifier, used in status queries or left empty for new
    /// requests.
    #[serde(rename = "RequestID")]
    pub request_id: RequestId<'a>,
}

impl<'a> RequestSecurityToken<'a> {
    /// The XML namespace for WS-Trust.
    const XMLNS: &'static str = "http://docs.oasis-open.org/ws-sx/ws-trust/200512";

    /// Create a new request security token for issuing an X.509v3 certificate.
    ///
    /// # Arguments
    ///
    /// * `binary_security_token` - Token containing the certificate request.
    ///
    /// # Returns
    ///
    /// A new [`RequestSecurityToken`] configured for a certificate issuance
    /// request.
    #[must_use]
    pub fn new_issue_x509v3(binary_security_token: BinarySecurityToken<'a>) -> Self {
        Self {
            xmlns: Self::XMLNS.into(),
            token_type: TokenType::x509v3(),
            request_type: RequestType::Issue,
            binary_security_token: Some(binary_security_token),
            request_ket: None,
            request_id: RequestId::nil(),
        }
    }

    /// Creates a new request security token for a Key Exchange Token request.
    ///
    /// # Returns
    ///
    /// A new [`RequestSecurityToken`] configured for a Key Exchange Token
    /// request.
    #[must_use]
    pub fn new_key_exchange_token() -> Self {
        Self {
            xmlns: Self::XMLNS.into(),
            token_type: TokenType::x509v3(),
            request_type: RequestType::KeyExchangeToken,
            binary_security_token: None,
            request_ket: Some(()),
            request_id: RequestId::nil(),
        }
    }

    /// Creates a new request security token for querying token status.
    ///
    /// # Arguments
    ///
    /// * `request_id` - The identifier of the original certificate request.
    ///
    /// # Returns
    ///
    /// A new [`RequestSecurityToken`] configured for querying token status.
    #[must_use]
    pub fn new_query_token_status(request_id: &'a str) -> Self {
        Self {
            xmlns: Self::XMLNS.into(),
            token_type: TokenType::x509v3(),
            request_type: RequestType::QueryTokenStatus,
            binary_security_token: None,
            request_ket: None,
            request_id: RequestId::new_with_id(request_id),
        }
    }
}

/// A `RequestType` as defined by section 3.1 of WSTrust1.3, subject to the
/// constraints defined by section 3.1.4.1.2.7 of MS-WSTEP.
#[non_exhaustive]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum RequestType {
    /// Request a new certificate to be issued.
    Issue,
    /// Query the status of a previously submitted certificate request.
    QueryTokenStatus,
    /// Request a Key Exchange Token from the server.
    KeyExchangeToken,
}

impl RequestType {
    /// The URI for the `Issue` request type.
    const RT_ISSUE: &str = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue";

    /// The URI for the `QueryTokenStatus` request type.
    const RT_QUERY_TOKEN_STATUS: &str =
        "http://schemas.microsoft.com/windows/pki/2009/01/enrollment/QueryTokenStatus";

    /// The URI for the `KeyExchangeToken` request type.
    const RT_KEY_EXCHANGE_TOKEN: &str = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/KET";
}

impl Serialize for RequestType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str((*self).into())
    }
}

impl From<RequestType> for &'static str {
    fn from(value: RequestType) -> Self {
        match value {
            RequestType::Issue => RequestType::RT_ISSUE,
            RequestType::QueryTokenStatus => RequestType::RT_QUERY_TOKEN_STATUS,
            RequestType::KeyExchangeToken => RequestType::RT_KEY_EXCHANGE_TOKEN,
        }
    }
}

impl FromStr for RequestType {
    type Err = RequestTypeParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let request_type = match s {
            Self::RT_ISSUE => Self::Issue,
            Self::RT_QUERY_TOKEN_STATUS => Self::QueryTokenStatus,
            Self::RT_KEY_EXCHANGE_TOKEN => Self::KeyExchangeToken,
            other => return Err(RequestTypeParseError(other.to_string())),
        };

        Ok(request_type)
    }
}

/// Error that occurs when parsing a string into a [`RequestType`] fails.
///
/// This error is returned when the input string does not match any of the
/// valid URIs for MS-WSTEP request types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestTypeParseError(String);

impl std::fmt::Display for RequestTypeParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} is not a valid MS-WSTEP request type", self.0)
    }
}

impl std::error::Error for RequestTypeParseError {}

#[cfg(test)]
mod request_security_token_tests {
    use crate::common::{serde_test_utils::se_test, BinarySecurityToken};

    use super::RequestSecurityToken;

    #[test]
    fn test_se_request_security_token() {
        let cms: &'static str =
            include_str!("../tests/data/standard_certificate_client_request.cms");
        let expected = format!(
            r#"<RequestSecurityToken xmlns="http://docs.oasis-open.org/ws-sx/ws-trust/200512"><TokenType>http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3</TokenType><RequestType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue</RequestType><BinarySecurityToken EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd#base64binary" ValueType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd#PKCS7" xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">{cms}</BinarySecurityToken><RequestID xsi:nil="true" xmlns="http://schemas.microsoft.com/windows/pki/2009/01/enrollment"/></RequestSecurityToken>"#,
        );
        let actual =
            RequestSecurityToken::new_issue_x509v3(BinarySecurityToken::new_pkcs7_base64(cms));
        se_test(&expected, &actual);
    }
}
