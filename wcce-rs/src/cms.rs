#![allow(clippy::module_name_repetitions)]

use std::str::FromStr;

use crate::{
    attributes::EnrollmentNameValuePair,
    pkcs10::CertificateRequest,
    signing::{SigningCertificate, SigningKey},
};

use base64::Engine;
use bcder::{
    encode::{Primitive, PrimitiveContent},
    Captured, Mode, Tag,
};
use cryptographic_message_syntax::{CmsError, Oid, SignedDataBuilder, SignerBuilder};
use x509_certificate::rfc5652::AttributeValue;

/// A CMS-based certificate request.
#[derive(Debug)]
pub struct CmsCertificateRequest;

impl CmsCertificateRequest {
    /// Start building a new CMS-based certificate request.
    #[must_use]
    pub const fn builder<'a>() -> CmsCertificateRequestBuilder<'a> {
        CmsCertificateRequestBuilder::new()
    }
}

/// Used to build a [`CmsCertificateRequest`].
/// See [`CmsCertificateRequest::builder`] to get started.
#[derive(Debug)]
pub struct CmsCertificateRequestBuilder<'a> {
    signed_name_value_pairs: Vec<EnrollmentNameValuePair<'a>>,
}

impl<'a> CmsCertificateRequestBuilder<'a> {
    /// OID for `pkiData` (§3.1.1.4.3.1.2 `szOID_PKCS_7_DATA`).
    const CMS_DATA_OID: &'static str = "1.2.840.113549.1.7.1";

    /// Create a new [`CmsCertificateRequestBuilder`].
    const fn new() -> Self {
        Self {
            signed_name_value_pairs: Vec::new(),
        }
    }

    /// Build the request into a [`CmsCertificateRequest`].
    ///
    /// # Errors
    /// Returns an error if the signed CMS cannot be serialized.
    pub fn build(
        self,
        pkcs10_csr: &CertificateRequest,
        key: &SigningKey,
        cert: &SigningCertificate,
    ) -> Result<String, CmsCertificateRequestBuildError> {
        let cms_data_oid = Oid::from_str(Self::CMS_DATA_OID)?;
        let mut signer_builder =
            SignerBuilder::new(&key.key_cms, cert.cert.clone()).content_type(cms_data_oid.clone());

        for name_value_pair in self.signed_name_value_pairs {
            let envp_oid = EnrollmentNameValuePair::ATTRIBUTE_OID_STR.parse()?;
            let name = BMPString::new(name_value_pair.name());
            let value = BMPString::new(name_value_pair.value());
            let sequence = bcder::encode::sequence((name.encode(), value.encode()));
            let attr_value = AttributeValue::new(Captured::from_values(Mode::Der, sequence));
            signer_builder = signer_builder.signed_attribute(envp_oid, vec![attr_value]);
        }

        let der_encoded = SignedDataBuilder::default()
            .content_inline(pkcs10_csr.as_der().to_vec())
            .content_type(cms_data_oid)
            .signer(signer_builder)
            .build_der()?;

        let cms = base64::engine::general_purpose::STANDARD.encode(der_encoded);
        Ok(cms)
    }

    /// Add a signed enrollment name-value pair CMS attribute to the request.
    #[must_use]
    pub fn add_signed_name_value_pair(mut self, envp: EnrollmentNameValuePair<'a>) -> Self {
        self.signed_name_value_pairs.push(envp);
        self
    }
}

/// Represents an ASN.1 [`BMPString`].
/// [`BMPString`] is also known as `UNICODE_STRING` in Microsoft's Certificate Enrollment API.
/// "BMP" refers to Unicode's "Basic Multilingual Plane".
struct BMPString(Vec<u8>);

impl BMPString {
    pub fn new(s: &str) -> Self {
        // BMPStrings MUST be big-endian UTF-16 encoded
        Self(Self::utf8_to_be_utf16(s))
    }

    /// Encode as a [`bcder::encode::Primitive`] of type [`bcder::tag::Tag::BMP_STRING`].
    pub fn encode(&self) -> Primitive<&[u8]> {
        self.0.encode_as(Tag::BMP_STRING)
    }

    /// Encodes a UTF-8 string as big-endian UTF-16 flattened into a [`Vec<u8>`].
    fn utf8_to_be_utf16(data: &str) -> Vec<u8> {
        let mut u8_encoded: Vec<u8> = vec![];
        for item in data.encode_utf16() {
            // Also, "be" stands for "big-endian"
            for byte in item.to_be_bytes() {
                u8_encoded.push(byte);
            }
        }
        u8_encoded
    }
}

/// Errors that may occur when building a CMS-based certificate request.
#[derive(Debug)]
pub enum CmsCertificateRequestBuildError {
    OidParse(&'static str),
    DerEncode(CmsError),
}

impl std::fmt::Display for CmsCertificateRequestBuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::OidParse(e) => write!(f, "failed to parse OID: {e}"),
            Self::DerEncode(e) => write!(f, "failed to build CMS: {e}"),
        }
    }
}

impl std::error::Error for CmsCertificateRequestBuildError {}

impl From<&'static str> for CmsCertificateRequestBuildError {
    fn from(value: &'static str) -> Self {
        Self::OidParse(value)
    }
}

impl From<CmsError> for CmsCertificateRequestBuildError {
    fn from(value: CmsError) -> Self {
        Self::DerEncode(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cms_certificate_request_builder_build() {
        assert!(CmsCertificateRequest::builder()
            .build(
                &CertificateRequest::builder()
                    .build(&SigningKey::new_testing_key())
                    .unwrap(),
                &SigningKey::new_testing_key(),
                &SigningCertificate::new_testing_cert(),
            )
            .is_ok());

        assert!(CmsCertificateRequest::builder()
            .add_signed_name_value_pair(EnrollmentNameValuePair::CertificateTemplate {
                cn: "MyTemplate",
            })
            .build(
                &CertificateRequest::builder()
                    .build(&SigningKey::new_testing_key())
                    .unwrap(),
                &SigningKey::new_testing_key(),
                &SigningCertificate::new_testing_cert(),
            )
            .is_ok());
    }
}
