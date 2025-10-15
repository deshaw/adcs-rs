use rcgen::{ExtendedKeyUsagePurpose, KeyUsagePurpose};

use crate::signing::SigningKey;

/// A PKCS #10 certificate signing request (CSR).
pub struct CertificateRequest {
    inner: rcgen::CertificateSigningRequest,
}

impl CertificateRequest {
    /// Start building a new PKCS #10 [`CertificateRequest`].
    ///
    /// The subject of the resulting request will be a distinguished name containing
    /// a single common name (CN) attribute with the value [`CertificateRequestBuilder::DEFAULT_CSR_SUBJECT_CN`].
    ///
    /// This is useful for certificate templates that construct their subject from the requester's Active Directory
    /// attributes (i.e., the template has `Subject Name` > `Supply in the request` unset).
    /// The placeholder subject is technically required, but will not be used in the signed certificate.
    ///
    /// # Examples
    ///
    /// ```
    /// use wcce_rs::{pkcs10::{CertificateRequest, KeyUsage, ExtendedKeyUsage}, signing::SigningKey};
    ///
    /// let key_pem = include_str!("../test/example.ec.pem.key");
    /// let signing_key = SigningKey::from_pem(key_pem).unwrap();
    /// CertificateRequest::builder()
    ///     .add_key_usage(KeyUsage::DigitalSignature)
    ///     .add_key_usage(KeyUsage::KeyEncipherment)
    ///     .add_extended_key_usage(ExtendedKeyUsage::ClientAuth)
    ///     .build(&signing_key);
    /// ```
    #[must_use]
    pub fn builder() -> CertificateRequestBuilder {
        CertificateRequestBuilder::new_with_default_subject()
    }

    /// Return the DER-encoded bytes of the underlying request.
    #[must_use]
    pub fn as_der(&self) -> &[u8] {
        self.inner.der().as_ref()
    }

    /// Serialize the request as a PEM-encoded string.
    ///
    /// # Errors
    /// Returns an error if the request cannot be serialized to PEM.
    pub fn to_pem(&self) -> Result<String, CertificateRequestPemError> {
        Ok(self.inner.pem()?)
    }
}

impl std::fmt::Debug for CertificateRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CertificateRequest").finish()
    }
}

/// Used to build a [`CertificateRequest`].
/// See [`CertificateRequest::builder`] to get started.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateRequestBuilder {
    params: rcgen::CertificateParams,
    custom_attributes: Vec<rcgen::Attribute>,
}

impl CertificateRequestBuilder {
    /// The default common name to be used as the subject of a certificate signing request.
    pub const DEFAULT_CSR_SUBJECT_CN: &str = "MS-WCCE certificate signing request";

    /// Create a new [`CertificateRequestBuilder`] with a default subject of [`Self::DEFAULT_CSR_SUBJECT_CN`].
    fn new_with_default_subject() -> Self {
        // Would use struct expression to override default values, but this type is #[non_exhaustive]
        let mut params = rcgen::CertificateParams::default();
        params.distinguished_name = rcgen::DistinguishedName::new();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, Self::DEFAULT_CSR_SUBJECT_CN);

        Self {
            params,
            custom_attributes: Vec::new(),
        }
    }

    /// Build the request into a [`CertificateRequest`].
    ///
    /// # Errors
    /// Returns an error if certificate signing request serialization fails.
    pub fn build(
        self,
        key: &SigningKey,
    ) -> Result<CertificateRequest, CertificateRequestBuildError> {
        let csr = self
            .params
            .serialize_request_with_attributes(&key.key_rcgen, self.custom_attributes)?;
        Ok(CertificateRequest { inner: csr })
    }

    /// Add a [`KeyUsage`] to the built request.
    #[must_use]
    pub fn add_key_usage(mut self, key_usage: KeyUsage) -> Self {
        self.params.key_usages.push(key_usage.into());
        self
    }

    /// Add an [`ExtendedKeyUsage`] to the built request.
    #[must_use]
    pub fn add_extended_key_usage(mut self, extended_key_usage: ExtendedKeyUsage) -> Self {
        self.params
            .extended_key_usages
            .push(extended_key_usage.into());
        self
    }

    /// Add an [`Extension`] to the built request.
    #[must_use]
    pub fn add_extension(mut self, extension: &impl Extension) -> Self {
        let mut ext = rcgen::CustomExtension::from_oid_content(extension.oid(), extension.value());
        ext.set_criticality(extension.critical());
        self.params.custom_extensions.push(ext);
        self
    }

    /// Add an [`Attribute`] to the built request.
    #[must_use]
    pub fn add_attribute(mut self, attribute: &impl Attribute) -> Self {
        self.custom_attributes.push(rcgen::Attribute {
            oid: attribute.oid(),
            values: attribute.values(),
        });
        self
    }
}

/// Types that implement [`Attribute`] may be encoded as an attribute as
/// defined by [RFC 5280][1] and later constrained by [PKCS #10][2]:
///
/// RFC 5280:
/// ```asn1
/// Attribute ::= SEQUENCE {
///     type    AttributeType,
///     values  SET OF AttributeValue
/// }
/// ```
///
/// PKCS #10:
/// ```asn1
/// Attribute { ATTRIBUTE:IOSet } ::= SEQUENCE {
///     type    ATTRIBUTE.&id({IOSet}),
///     values  SET SIZE(1..MAX) OF ATTRIBUTE.&Type({IOSet}{@type})
/// }
/// ```
///
/// [1]: <https://datatracker.ietf.org/doc/html/rfc5280#appendix-A.1>
/// [2]: <https://datatracker.ietf.org/doc/html/rfc2986#section-4>
pub trait Attribute {
    /// Attribute type as defined by [RFC 5280][1]:
    ///
    /// ```asn1
    /// AttributeType ::= OBJECT IDENTIFIER
    /// ```
    ///
    /// [1]: <https://datatracker.ietf.org/doc/html/rfc5280#appendix-A.1>
    fn oid(&self) -> &'static [u64];

    /// Attribute values as defined by [RFC 5280][1]:
    ///
    /// Values are defined as a  SET OF `AttributeValue`:
    /// ```asn1
    /// values  SET OF AttributeValue
    /// ```
    ///
    /// `AttributeValue` is defined as `ANY`:
    /// ```asn1
    /// AttributeValue ::= ANY -- DEFINED BY AttributeType
    /// ```
    ///
    /// [1]: <https://datatracker.ietf.org/doc/html/rfc5280#appendix-A.1>
    fn values(&self) -> Vec<u8>;
}

/// Types that implement [`Extension`] may be encoded as a certificate
/// extension as defined by [RFC 5280][1]:
///
/// ```asn1
/// Extension  ::=  SEQUENCE  {
///     extnID      OBJECT IDENTIFIER,
///     critical    BOOLEAN DEFAULT FALSE,
///     extnValue   OCTET STRING
///                 -- contains the DER encoding of an ASN.1 value
///                 -- corresponding to the extension type identified
///                 -- by extnID
/// }
/// ```
///
/// [1]: <https://datatracker.ietf.org/doc/html/rfc5280>
pub trait Extension {
    /// Extension ID as defined by [RFC 5280]:
    ///
    /// ```asn1
    /// extnID      OBJECT IDENTIFIER,
    /// ```
    ///
    /// [1]: <https://datatracker.ietf.org/doc/html/rfc5280>
    fn oid(&self) -> &[u64];

    /// Extension criticality as defined by [RFC 5280]:
    ///
    /// ```asn1
    /// critical    BOOLEAN DEFAULT FALSE,
    /// ```
    ///
    /// [1]: <https://datatracker.ietf.org/doc/html/rfc5280>
    fn critical(&self) -> bool;

    /// DER-encoded extension value as defined by [RFC 5280]:
    ///
    /// ```asn1
    /// extnValue   OCTET STRING
    ///             -- contains the DER encoding of an ASN.1 value
    ///             -- corresponding to the extension type identified
    ///             -- by extnID
    /// ```
    ///
    /// [1]: <https://datatracker.ietf.org/doc/html/rfc5280>
    fn value(&self) -> Vec<u8>;
}

/// A key usage value as defined by [section 4.2.1.3 of RFC 5280][1]
///
/// [1]: <https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.3>
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyUsage {
    DigitalSignature,
    /// Also known as "nonRepudiation".
    ContentCommitment,
    KeyEncipherment,
    DataEncipherment,
    KeyAgreement,
    KeyCertSign,
    CrlSign,
    EncipherOnly,
    DecipherOnly,
}

impl From<KeyUsage> for KeyUsagePurpose {
    fn from(value: KeyUsage) -> Self {
        match value {
            KeyUsage::DigitalSignature => Self::DigitalSignature,
            KeyUsage::ContentCommitment => Self::ContentCommitment,
            KeyUsage::KeyEncipherment => Self::KeyEncipherment,
            KeyUsage::DataEncipherment => Self::DataEncipherment,
            KeyUsage::KeyAgreement => Self::KeyAgreement,
            KeyUsage::KeyCertSign => Self::KeyCertSign,
            KeyUsage::CrlSign => Self::CrlSign,
            KeyUsage::EncipherOnly => Self::EncipherOnly,
            KeyUsage::DecipherOnly => Self::DecipherOnly,
        }
    }
}

/// An extended key usage value as defined by [section 4.2.1.12 of RFC 5280][1].
///
/// This enumeration contains the following Microsoft-specific variants:
/// - [`ExtendedKeyUsage::SmartCardLogon`]
///
/// [1]: <https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.12>
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExtendedKeyUsage {
    Any,
    ServerAuth,
    ClientAuth,
    CodeSigning,
    EmailProtection,
    TimeStamping,
    OcspSigning,
    SmartCardLogon,
    Other(Vec<u64>),
}

impl ExtendedKeyUsage {
    /// Smartcard logon (`extKeyUsage` extension) OID (`XCN_OID_KP_SMARTCARD_LOGON`).
    /// "The certificate enables an individual to log on to a computer by using a smart card".
    /// Smart cards operate "on behalf of" their users.
    const SMARTCARD_LOGON_OID: &[u64] = &[1, 3, 6, 1, 4, 1, 311, 20, 2, 2];
}

impl From<ExtendedKeyUsage> for ExtendedKeyUsagePurpose {
    fn from(value: ExtendedKeyUsage) -> Self {
        match value {
            ExtendedKeyUsage::Any => Self::Any,
            ExtendedKeyUsage::ServerAuth => Self::ServerAuth,
            ExtendedKeyUsage::ClientAuth => Self::ClientAuth,
            ExtendedKeyUsage::CodeSigning => Self::CodeSigning,
            ExtendedKeyUsage::EmailProtection => Self::EmailProtection,
            ExtendedKeyUsage::TimeStamping => Self::TimeStamping,
            ExtendedKeyUsage::OcspSigning => Self::OcspSigning,
            ExtendedKeyUsage::SmartCardLogon => {
                Self::Other(ExtendedKeyUsage::SMARTCARD_LOGON_OID.into())
            }
            ExtendedKeyUsage::Other(vec) => Self::Other(vec),
        }
    }
}

/// Errors that may occur when building a PKCS #10 certificate request.
#[derive(Debug, PartialEq, Eq)]
pub struct CertificateRequestBuildError(rcgen::Error);

impl std::fmt::Display for CertificateRequestBuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "failed to build and sign certificate request: {}",
            self.0
        )
    }
}

impl std::error::Error for CertificateRequestBuildError {}

impl From<rcgen::Error> for CertificateRequestBuildError {
    fn from(value: rcgen::Error) -> Self {
        Self(value)
    }
}

/// Errors that may occur when serializing a certificate request to PEM.
#[derive(Debug, PartialEq, Eq)]
pub struct CertificateRequestPemError(rcgen::Error);

impl std::fmt::Display for CertificateRequestPemError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "failed to serialize PEM certificate request: {}", self.0)
    }
}

impl std::error::Error for CertificateRequestPemError {}

impl From<rcgen::Error> for CertificateRequestPemError {
    fn from(value: rcgen::Error) -> Self {
        Self(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_certificate_request_builder_build() {
        assert!(CertificateRequest::builder()
            .build(&SigningKey::new_testing_key())
            .is_ok());

        assert!(CertificateRequest::builder()
            .add_key_usage(KeyUsage::DigitalSignature)
            .add_key_usage(KeyUsage::KeyEncipherment)
            .add_extended_key_usage(ExtendedKeyUsage::ClientAuth)
            .build(&SigningKey::new_testing_key())
            .is_ok());
    }
}
