use std::{borrow::Cow, str::FromStr};

use serde::{Deserialize, Deserializer, Serialize};

/// A header for a request or a response in the WS-Trust X.509v3 Token
/// Enrollment Extensions (MS-WSTEP) protocol.
///
/// This structure represents the SOAP header fields used in MS-WSTEP message
/// exchanges between clients and the Security Token Service (STS). Headers
/// contain addressing information, correlation identifiers, and other metadata
/// needed for proper message routing and processing.
///
/// The MS-WSTEP protocol follows the WS-Addressing specification, using
/// elements like [`Action`], message ID, relates to, and [`ReplyTo`] to
/// facilitate proper message delivery and correlation.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
pub struct Header<'a> {
    /// The [`Action`] identifier for this request or response.
    ///
    /// Specifies the intent of the message. In MS-WSTEP, common actions
    /// include certificate enrollment requests, responses, and fault messages.
    /// This field is required and must be understood by the recipient.
    #[serde(rename = "a:Action")]
    #[serde(alias = "Action")]
    pub action: Action,

    /// An optional [`ActivityId`] used for diagnostic correlation.
    ///
    /// Primarily used by the server to correlate requests and responses for
    /// logging and troubleshooting purposes. This value helps trace message
    /// processing across system components.
    #[serde(rename = "ActivityId", skip_serializing_if = "Option::is_none")]
    pub activity_id: Option<ActivityId<'a>>,

    /// The message ID of the request that this response pertains to.
    ///
    /// For response messages, this field contains the message ID of the
    /// original request. This enables correlation between requests and their
    /// corresponding responses.
    #[serde(
        rename = "a:RelatesTo",
        alias = "RelatesTo",
        skip_serializing_if = "Option::is_none"
    )]
    pub relates_to: Option<Cow<'a, str>>,

    /// The self-specified message ID of this request.
    ///
    /// A unique identifier for this message, typically formatted as a UUID URI
    /// (e.g. `"urn:uuid:b5d1a601-5091-4a7d-b34b-5204c18b5919"`)
    /// Used for correlation when the recipient needs to reference this message
    /// in future communications.
    #[serde(
        rename = "a:MessageID",
        alias = "MessageID",
        skip_serializing_if = "Option::is_none"
    )]
    pub message_id: Option<Cow<'a, str>>,

    /// Specifies where responses to this message should be sent.
    ///
    /// In client requests, this typically contains the anonymous address
    /// indicating that responses should be sent back on the same connection.
    #[serde(
        rename = "a:ReplyTo",
        alias = "ReplyTo",
        skip_serializing_if = "Option::is_none"
    )]
    pub reply_to: Option<ReplyTo<'a>>,

    /// Specifies the ultimate recipient of this message.
    ///
    /// The intended destination address for this message, which may differ
    /// from the transport-level address if intermediaries are involved.
    #[serde(rename = "a:To", alias = "To", skip_serializing_if = "Option::is_none")]
    pub to: Option<To<'a>>,
}

impl<'a> Header<'a> {
    /// Creates a new request header with the specified parameters.
    ///
    /// # Parameters
    ///
    /// * `action_type` - The type of action being requested
    /// * `message_id` - A unique identifier for this request, typically a UUID
    /// * `to` - Optional destination address for the message
    /// * `reply_to` - Optional address where responses should be sent
    ///
    /// # Returns
    ///
    /// A new [`Header`] configured for a client request
    #[must_use]
    pub fn new_request_header(
        action_type: ActionType,
        message_id: &'a str,
        to: Option<&'a str>,
        reply_to: Option<&'a str>,
    ) -> Self {
        Self {
            action: Action::new(action_type),
            activity_id: None,
            relates_to: None,
            message_id: Some(message_id.into()),
            reply_to: reply_to.map(ReplyTo::new),
            to: to.map(To::new),
        }
    }

    /// Creates a new response header with the specified parameters.
    ///
    /// # Parameters
    ///
    /// * `action_type` - The type of response action
    /// * `activity_id` - Correlation identifier for diagnostic purposes
    /// * `relates_to` - Message ID of the request this response pertains to
    ///
    /// # Returns
    ///
    /// A new [`Header`] configured for a server response
    #[must_use]
    pub fn new_response_header(
        action_type: ActionType,
        activity_id: ActivityId<'a>,
        relates_to: &'a str,
    ) -> Self {
        Self {
            action: Action::new(action_type),
            activity_id: Some(activity_id),
            relates_to: Some(relates_to.into()),
            message_id: None,
            reply_to: None,
            to: None,
        }
    }
}

/// Destination address for a SOAP message in the WS-Trust X.509v3 Token
/// Enrollment Protocol.
///
/// This struct represents the "To" addressing header field as defined in
/// WS-Addressing. The field indicates the ultimate recipient of this message
/// in the MS-WSTEP protocol. It typically contains the URL of the Security
/// Token Service (STS) endpoint.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
pub struct To<'a> {
    /// Indicates that this header field must be understood and processed by
    /// the recipient.
    #[serde(rename = "@s:mustUnderstand")]
    #[serde(alias = "@mustUnderstand")]
    pub must_understand: MustUnderstand,

    /// The actual destination address for this message.
    ///
    /// This is typically a URL of the Security Token Service endpoint that
    /// should receive and process this message.
    #[serde(rename = "$text")]
    pub value: Cow<'a, str>,
}

impl<'a> To<'a> {
    /// Creates a new `To` addressing header with the specified destination
    /// address.
    ///
    /// By default, sets `must_understand` to `true` to indicate this header
    /// must be processed by the recipient.
    ///
    /// # Parameters
    ///
    /// * `value` - The destination address to which the message is being sent
    ///
    /// # Returns
    ///
    /// A new `To` instance with the specified address value
    #[must_use]
    pub fn new(value: &'a str) -> Self {
        Self {
            must_understand: MustUnderstand(true),
            value: value.into(),
        }
    }
}

/// Reply address information for a SOAP message in the WS-Trust protocol.
///
/// This struct represents the "reply to" addressing header field as defined in
/// WS-Addressing. It specifies where responses to this message should be sent.
/// In MS-WSTEP, this typically contains an anonymous address indicating that
/// responses should be sent back on the same connection.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
pub struct ReplyTo<'a> {
    /// The address to which replies should be sent.
    ///
    /// In MS-WSTEP client requests, this typically contains the anonymous
    /// address [`crate::request::WstepRequest::REPLY_TO_ANONYMOUS`] indicating
    /// that responses should be sent back on the same connection.
    #[serde(rename = "a:Address")]
    #[serde(alias = "Address")]
    pub address: Address<'a>,
}

impl<'a> ReplyTo<'a> {
    /// Creates a new `ReplyTo` addressing header with the specified reply
    /// address.
    ///
    /// # Parameters
    ///
    /// * `address` - The address to which responses should be sent
    ///
    /// # Returns
    ///
    /// A new `ReplyTo` instance with the specified address
    fn new(address: &'a str) -> Self {
        Self {
            address: Address {
                value: address.into(),
            },
        }
    }
}

/// An address specification used in WS-Addressing headers.
///
/// Represents a URI address within WS-Addressing headers like [`ReplyTo`].
/// Contains the actual address value as a string.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
pub struct Address<'a> {
    /// The actual address value as a string.
    #[serde(rename = "$text")]
    pub value: Cow<'a, str>,
}

/// Diagnostic correlation identifier used in the MS-WSTEP protocol.
///
/// This element is used for logging and troubleshooting purposes.
/// It helps trace message processing across system components by providing
/// correlation identifiers that can be tracked in logs.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
pub struct ActivityId<'a> {
    /// A correlation identifier that links related activities.
    ///
    /// This identifier helps associate this activity with other related
    /// activities for end-to-end diagnostic tracing.
    #[serde(rename = "@CorrelationId")]
    pub correlation_id: Cow<'a, str>,

    /// The XML namespace for this element.
    #[serde(rename = "@xmlns")]
    pub xmlns: Cow<'a, str>,

    /// The unique identifier for this specific activity.
    ///
    /// This is the primary identifier that distinguishes this activity
    /// from other activities in the system.
    #[serde(rename = "$text")]
    pub value: Cow<'a, str>,
}

impl<'a> ActivityId<'a> {
    /// The standard XML namespace for `ServiceModel` Diagnostics.
    const XMLNS: &'static str = "http://schemas.microsoft.com/2004/09/ServiceModel/Diagnostics";

    /// Creates a new `ActivityId` with the specified id and correlation id.
    ///
    /// # Parameters
    ///
    /// * `id` - The unique identifier for this activity
    /// * `correlation_id` - An identifier that correlates this activity
    ///
    /// # Returns
    ///
    /// A new `ActivityId` with the specified identifiers
    #[must_use]
    pub fn new(id: &'a str, correlation_id: &'a str) -> Self {
        Self {
            correlation_id: correlation_id.into(),
            xmlns: Self::XMLNS.into(),
            value: id.into(),
        }
    }
}

/// Represents the SOAP action header for a WS-Trust X.509v3 Token Enrollment
/// message.
///
/// The Action element identifies the intent of the message. In MS-WSTEP,
/// common actions include certificate enrollment requests, responses, and
/// fault messages.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
pub struct Action {
    /// Indicates that this header field must be understood and processed by
    /// the recipient.
    #[serde(rename = "@s:mustUnderstand")]
    #[serde(alias = "@mustUnderstand")]
    pub must_understand: MustUnderstand,

    /// The specific [`ActionType`] that identifies the intent of this message.
    #[serde(rename = "$text")]
    pub action_type: ActionType,
}

impl Action {
    /// Creates a new `Action` header with the specified action type.
    ///
    /// By default, sets `must_understand` to `true` to indicate this header
    /// must be processed by the recipient.
    ///
    /// # Parameters
    ///
    /// * `action_type` - The specific action type for this message
    ///
    /// # Returns
    ///
    /// A new `Action` instance with the specified action typ
    #[must_use]
    pub const fn new(action_type: ActionType) -> Self {
        Self {
            must_understand: MustUnderstand(true),
            action_type,
        }
    }
}

/// A marker type for SOAP headers that must be understood by the recipient.
///
/// This type wraps a boolean value that indicates whether a SOAP header
/// must be understood and processed by the recipient. When set to `true`,
/// the recipient must either process the header or generate a fault.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct MustUnderstand(pub bool);

impl Serialize for MustUnderstand {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(if self.0 { "1" } else { "0" })
    }
}

impl<'a> Deserialize<'a> for MustUnderstand {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'a>,
    {
        let s = String::deserialize(deserializer)?;
        Ok(Self(s == "1"))
    }
}

/// Valid SOAP actions for MS-WSTEP messages as detailed in section 3.1.4.2
/// Processing Rules of MS-WSTEP.
#[non_exhaustive]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum ActionType {
    /// Request Security Token action.
    ///
    /// > If the SOAP action is "<http://schemas.microsoft.com/windows/pki/2009/01/enrollment/RST/wstep>",
    /// > the server must follow the Request Security Token Processing Rules per section 3.1.4.2.1.
    RequestSecurityToken,

    /// Request Security Token Response Collection action.
    RequestSecurityTokenResponseCollection,

    /// Key Exchange Token action.
    ///
    /// > If the SOAP action is "<http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/KET>",
    /// > the server must follow the Key Exchange Token Processing Rules per section 3.1.4.2.2.
    KeyExchangeToken,

    /// Key Exchange Token Final action.
    KeyExchangeTokenFinal,

    /// SOAP Fault action.
    SoapFault,

    /// Fault action.
    Fault,

    /// Fault Detail action.
    FaultDetail,
}

impl ActionType {
    const RST_WSTEP: &str = "http://schemas.microsoft.com/windows/pki/2009/01/enrollment/RST/wstep";

    const RSTRC_WSTEP: &str =
        "http://schemas.microsoft.com/windows/pki/2009/01/enrollment/RSTRC/wstep";

    const KET: &str = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/KET";

    const KET_FINAL: &str = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/RSTR/KETFinal";

    const FAULT: &str =
        "http://schemas.microsoft.com/net/2005/12/windowscommunicationfoundation/dispatcher/fault";

    const FAULT_DETAIL: &str = "http://schemas.microsoft.com/windows/pki/2009/01/enrollment/RequestSecurityTokenCertificateEnrollmentWSDetailFault";

    const SOAP_FAULT: &str = "http://www.w3.org/2005/08/addressing/soap/fault";
}

impl Serialize for ActionType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str((*self).into())
    }
}

impl<'de> Deserialize<'de> for ActionType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

impl From<ActionType> for &'static str {
    fn from(value: ActionType) -> Self {
        match value {
            ActionType::RequestSecurityToken => ActionType::RST_WSTEP,
            ActionType::RequestSecurityTokenResponseCollection => ActionType::RSTRC_WSTEP,
            ActionType::KeyExchangeToken => ActionType::KET,
            ActionType::KeyExchangeTokenFinal => ActionType::KET_FINAL,
            ActionType::Fault => ActionType::FAULT,
            ActionType::FaultDetail => ActionType::FAULT_DETAIL,
            ActionType::SoapFault => ActionType::SOAP_FAULT,
        }
    }
}

impl FromStr for ActionType {
    type Err = ActionTypeParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let action = match s {
            Self::RST_WSTEP => Self::RequestSecurityToken,
            Self::RSTRC_WSTEP => Self::RequestSecurityTokenResponseCollection,
            Self::KET => Self::KeyExchangeToken,
            Self::KET_FINAL => Self::KeyExchangeTokenFinal,
            Self::FAULT => Self::Fault,
            Self::FAULT_DETAIL => Self::FaultDetail,
            Self::SOAP_FAULT => Self::SoapFault,
            other => return Err(ActionTypeParseError(other.to_string())),
        };
        Ok(action)
    }
}

/// Errors that may occur when parsing an [`ActionType`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionTypeParseError(String);

impl std::fmt::Display for ActionTypeParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} is not a valid MS-WSTEP action type", self.0)
    }
}

impl std::error::Error for ActionTypeParseError {}

/// A security token that contains binary data encoded in base64.
///
/// This struct represents a `BinarySecurityToken` as defined in the
/// WS-Security specification, used within the MS-WSTEP protocol to carry
/// certificate requests and responses. The token contains binary data
/// (typically X.509 certificates or PKCS requests) with its format identified
/// by the [`ValueType`] and its encoding method specified by [`EncodingType`].
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
pub struct BinarySecurityToken<'a> {
    /// Specifies the encoding method used for the binary data.
    #[serde(rename = "@EncodingType")]
    pub encoding_type: EncodingType,

    /// Identifies the type of binary security token.
    #[serde(rename = "@ValueType")]
    pub value_type: ValueType,

    /// The XML namespace for the security token.
    #[serde(rename = "@xmlns")]
    pub xmlns: Cow<'a, str>,

    /// The actual binary data, encoded according to the encoding type.
    #[serde(rename = "$text")]
    pub value: Cow<'a, str>,
}

impl<'a> BinarySecurityToken<'a> {
    /// The standard XML namespace for WS-Security Security Extension.
    const XMLNS: &'static str =
        "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";

    /// Creates a new [`BinarySecurityToken`] with the specified parameters.
    ///
    /// # Parameters
    ///
    /// * `value` - The base64-encoded binary data
    /// * `value_type` - The type of the token (e.g., PKCS7, X509v3)
    /// * `encoding_type` - The encoding method
    ///
    /// # Returns
    ///
    /// A new `BinarySecurityToken` with the specified parameters
    #[must_use]
    pub fn new(value: &'a str, value_type: ValueType, encoding_type: EncodingType) -> Self {
        Self {
            value: value.into(),
            encoding_type,
            value_type,
            xmlns: Self::XMLNS.into(),
        }
    }

    /// Creates a new [`BinarySecurityToken`] for a PKCS #7 request with base64
    /// encoding.
    ///
    /// This is a convenience method for creating a token specifically for
    /// certificate requests using PKCS #7 format, which is commonly used
    /// in MS-WSTEP enrollment operations.
    ///
    /// # Parameters
    ///
    /// * `value` - The base64-encoded PKCS #7 data
    ///
    /// # Returns
    ///
    /// A new [`BinarySecurityToken`] configured for PKCS #7 data
    #[must_use]
    pub fn new_pkcs7_base64(value: &'a str) -> Self {
        Self::new(value, ValueType::Pkcs7, EncodingType::Base64Binary)
    }

    /// Creates a new [`BinarySecurityToken`] for an X.509v3 certificate with
    /// base64 encoding.
    ///
    /// This is a convenience method for creating a token specifically for
    /// X.509v3 certificates, which are commonly used in the responses
    /// from the Security Token Service.
    ///
    /// # Parameters
    ///
    /// * `value` - The base64-encoded X.509v3 certificate data
    ///
    /// # Returns
    ///
    /// A new [`BinarySecurityToken`] configured for X.509v3 data
    #[must_use]
    pub fn new_x509v3_base64(value: &'a str) -> Self {
        Self::new(value, ValueType::X509v3, EncodingType::Base64Binary)
    }
}

/// Indicates how the binary data in a [`BinarySecurityToken`] should be
/// interpreted.
#[non_exhaustive]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum ValueType {
    /// PKCS #7 data format, typically used for certificate requests.
    Pkcs7,
    /// X.509 version 3 certificate format, typically used for issued
    /// certificates.
    X509v3,
}

impl ValueType {
    /// The namespace URI for PKCS #7 token format.
    const NS_PKCS7: &'static str =
        "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd#PKCS7";

    /// The namespace URI for X.509v3 certificate format.
    const NS_X509V3: &'static str =
        "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3";
}

impl From<ValueType> for &'static str {
    fn from(value: ValueType) -> Self {
        match value {
            ValueType::Pkcs7 => ValueType::NS_PKCS7,
            ValueType::X509v3 => ValueType::NS_X509V3,
        }
    }
}

impl FromStr for ValueType {
    type Err = ValueTypeParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            Self::NS_PKCS7 => Self::Pkcs7,
            Self::NS_X509V3 => Self::X509v3,
            other => return Err(ValueTypeParseError(other.to_string())),
        })
    }
}

impl Serialize for ValueType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str((*self).into())
    }
}

impl<'de> Deserialize<'de> for ValueType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// Errors that may occur when parsing a [`ValueType`].
#[derive(Debug)]
pub struct ValueTypeParseError(String);

impl std::fmt::Display for ValueTypeParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} is not a valid MS-WSTEP BinarySecurityToken ValueType attribute",
            self.0
        )
    }
}

impl std::error::Error for ValueTypeParseError {}

/// Represents the different ways binary data can be encoded in the MS-WSTEP
/// protocol.
///
/// Currently, only base64 encoding is supported.
#[non_exhaustive]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum EncodingType {
    /// Base64 binary encoding as defined in the WS-Security specification.
    Base64Binary,
}

impl EncodingType {
    /// The namespace URI for base64 binary encoding.
    const NS_BASE64_BINARY: &'static str =
        "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd#base64binary";
}

impl From<EncodingType> for &'static str {
    fn from(value: EncodingType) -> Self {
        match value {
            EncodingType::Base64Binary => EncodingType::NS_BASE64_BINARY,
        }
    }
}

impl FromStr for EncodingType {
    type Err = EncodingTypeParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            Self::NS_BASE64_BINARY => Self::Base64Binary,
            other => return Err(EncodingTypeParseError(other.to_string())),
        })
    }
}

impl Serialize for EncodingType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str((*self).into())
    }
}

impl<'de> Deserialize<'de> for EncodingType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// Errors that may occur when parsing an [`EncodingType`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodingTypeParseError(String);

impl std::fmt::Display for EncodingTypeParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} is not a valid MS-WSTEP BinarySecurityToken EncodingType attribute",
            self.0
        )
    }
}

impl std::error::Error for EncodingTypeParseError {}

/// A request identifier used in the MS-WSTEP protocol.
///
/// This is a string identifier used to identify certificate requests,
/// particularly for pending requests that can be queried later with the
/// "query token status" operation.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RequestId<'a> {
    /// The actual request identifier value.
    ///
    /// If the request doesn't have an ID (for new requests), this will be None
    /// and `xsi_nil` will be set to true.
    #[serde(rename = "$text", skip_serializing_if = "Option::is_none")]
    pub value: Option<Cow<'a, str>>,

    /// Indicates whether this element is nil (has no value).
    ///
    /// When true, indicates this is an empty request ID.
    #[serde(
        rename = "@xsi:nil",
        alias = "@nil",
        skip_serializing_if = "Option::is_none"
    )]
    pub xsi_nil: Option<bool>,

    /// The XML namespace for this element.
    #[serde(rename = "@xmlns", skip_serializing_if = "Option::is_none")]
    pub xmlns: Option<Cow<'a, str>>,
}

/// A string identifier used to identify a request as defined by section
/// 3.1.4.1.2.4 of MS-WSTEP.
impl<'a> RequestId<'a> {
    /// The standard XML namespace for Windows PKI enrollment.
    const XMLNS: &'static str = "http://schemas.microsoft.com/windows/pki/2009/01/enrollment";

    /// Creates a new [`RequestId`] with the specified ID value.
    ///
    /// # Parameters
    ///
    /// * `id` - An optional request identifier. If [`None`], creates a nil ID.
    ///
    /// # Returns
    ///
    /// A new [`RequestId`] with the specified parameters
    #[must_use]
    pub fn new(id: Option<&'a str>) -> Self {
        Self {
            xsi_nil: if id.is_some() { None } else { Some(true) },
            value: id.map(Into::into),
            xmlns: Some(Self::XMLNS.into()),
        }
    }

    /// Creates a new [`RequestId`] with the specified ID value.
    ///
    /// A convenience method for creating a [`RequestId`] with a specific ID,
    /// typically used when querying the status of a pending request.
    ///
    /// # Parameters
    ///
    /// * `id` - The request identifier to use
    ///
    /// # Returns
    ///
    /// A new [`RequestId`] with the specified ID
    #[must_use]
    pub fn new_with_id(id: &'a str) -> Self {
        Self::new(Some(id))
    }

    /// Creates a new nil [`RequestId`] with no identifier.
    ///
    /// A convenience method for creating an empty [`RequestId`], typically
    /// used in new certificate requests.
    ///
    /// # Returns
    ///
    /// A new nil [`RequestId`]
    #[must_use]
    pub fn nil() -> Self {
        Self::new(None)
    }
}

/// A `TokenType` as defined by section 3.1 of WSTrust1.3, subject to the
/// constraints defined by 3.1.4.1.2.8 of MS-WSTEP.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
pub struct TokenType<'a> {
    #[serde(rename = "$text")]
    pub value: Cow<'a, str>,
}

impl<'a> TokenType<'a> {
    /// From section 3.1.4.1.2.8 of MS-WSTEP:
    /// > For the X.509v3 enrollment extension to WS-Trust, the <wst:tokentype> element MUST be...
    pub const X509V3_TOKEN_TYPE: &'static str =
        "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3";

    /// Create a new X.509v3 `TokenType`.
    #[must_use]
    pub fn x509v3() -> Self {
        Self {
            value: Self::X509V3_TOKEN_TYPE.into(),
        }
    }

    /// Create a `TokenType` with a value other than X.509.v3.
    #[must_use]
    pub fn other(value: impl Into<Cow<'a, str>>) -> Self {
        Self {
            value: value.into(),
        }
    }
}

#[cfg(test)]
pub(crate) mod common_serde_tests {
    use crate::common::BinarySecurityToken;

    use super::{
        serde_test_utils::{serde_test, serde_test_with_root},
        RequestId, TokenType,
    };

    #[test]
    fn test_serde_request_id() {
        let serialized_id = r#"<RequestID xmlns="http://schemas.microsoft.com/windows/pki/2009/01/enrollment">61</RequestID>"#;
        let value_id = RequestId::new(Some("61"));
        serde_test_with_root(serialized_id, value_id, "RequestID");

        let serialized_nil = r#"<RequestID xsi:nil="true" xmlns="http://schemas.microsoft.com/windows/pki/2009/01/enrollment"/>"#;
        let value_nil = RequestId::new(None);
        serde_test_with_root(serialized_nil, value_nil, "RequestID");
    }

    #[test]
    fn test_serde_token_type() {
        let serialized = "<TokenType>http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3</TokenType>";
        let value = TokenType::x509v3();
        serde_test(serialized, value);
    }

    #[test]
    fn test_serde_binary_security_token() {
        let cms = include_str!("../tests/data/standard_certificate_client_request.cms");
        let serialized = format!(
            r#"<BinarySecurityToken EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd#base64binary" ValueType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd#PKCS7" xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">{cms}</BinarySecurityToken>"#
        );
        let value = BinarySecurityToken::new_pkcs7_base64(cms);
        serde_test(&serialized, value);
    }
}

#[cfg(test)]
pub(crate) mod serde_test_utils {
    use std::fmt::Debug;

    use pretty_assertions::assert_eq;
    use serde::{Deserialize, Serialize};

    pub fn se_test<T>(expected_serialized: &str, value: &T)
    where
        T: Serialize + PartialEq + Eq + Debug,
    {
        se_test_inner(value, expected_serialized, None);
    }

    pub fn serde_test<'de, T>(serialized: &'de str, value: T)
    where
        T: Serialize + Deserialize<'de> + PartialEq + Eq + Debug,
    {
        serde_test_inner(serialized, value, None);
    }

    pub fn serde_test_with_root<'de, T>(serialized: &'de str, value: T, root_tag: &'de str)
    where
        T: Serialize + Deserialize<'de> + PartialEq + Eq + Debug,
    {
        serde_test_inner(serialized, value, Some(root_tag));
    }

    fn serde_test_inner<'de, T>(serialized: &'de str, value: T, se_with_root: Option<&'de str>)
    where
        T: Serialize + Deserialize<'de> + PartialEq + Eq + Debug,
    {
        se_test_inner(&value, serialized, se_with_root);
        de_test_inner(serialized, value);
    }

    fn se_test_inner<T>(value: &T, expected_serialized: &str, se_with_root: Option<&str>)
    where
        T: Serialize + PartialEq + Eq + Debug,
    {
        let actual_serialized = se_with_root.map_or_else(
            || quick_xml::se::to_string(&value).unwrap(),
            |root_tag| quick_xml::se::to_string_with_root(root_tag, &value).unwrap(),
        );
        assert_eq!(expected_serialized, actual_serialized);
    }

    fn de_test_inner<'de, T>(serialized: &'de str, value: T)
    where
        T: Serialize + Deserialize<'de> + PartialEq + Eq + Debug,
    {
        let expected_deserialized = value;
        let actual_deserialized: T = quick_xml::de::from_str(serialized).unwrap();
        assert_eq!(expected_deserialized, actual_deserialized);
    }
}
