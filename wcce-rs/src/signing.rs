#![allow(clippy::module_name_repetitions)]

use rcgen::KeyPair;
use x509_certificate::{CapturedX509Certificate, InMemorySigningKeyPair};

/// A key used for signing operations.
pub struct SigningKey {
    pub(crate) key_rcgen: KeyPair,
    pub(crate) key_cms: InMemorySigningKeyPair,
}

impl SigningKey {
    /// Parse a signing key from a PKCS #8 PEM-encoded string.
    ///
    /// # Errors
    /// Returns an error if the given string isn't a valid PKCS #8 PEM-encoded key.
    pub fn from_pem(pem_str: &str) -> Result<Self, SigningKeyParseError> {
        let key_rcgen = KeyPair::from_pem(pem_str)?;
        let key_cms = InMemorySigningKeyPair::from_pkcs8_pem(pem_str)?;
        Ok(Self { key_rcgen, key_cms })
    }

    /// Parse a signing key from a PKCS #8 DER-encoded buffer.
    ///
    /// # Errors
    /// Returns an error if the given buffer isn't a valid PKCS #8 DER-encoded key.
    pub fn from_der(der: &[u8]) -> Result<Self, SigningKeyParseError> {
        let key_rcgen = KeyPair::try_from(der)?;
        let key_cms = InMemorySigningKeyPair::from_pkcs8_der(der)?;
        Ok(Self { key_rcgen, key_cms })
    }
}

impl std::fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SigningKey").finish()
    }
}

/// A certificate used for signing operations.
#[derive(Debug, Clone)]
pub struct SigningCertificate {
    pub(crate) cert: CapturedX509Certificate,
}

impl SigningCertificate {
    /// Parse an X.509 signing certificate from a PEM-encoded string.
    ///
    /// # Errors
    /// Returns an error if the given string isn't a valid PEM-encoded X.509 certificate.
    pub fn from_pem(pem_str: &str) -> Result<Self, SigningCertificateParseError> {
        let cert = CapturedX509Certificate::from_pem(pem_str)?;
        Ok(Self { cert })
    }

    /// Parse a signing certificate from a DER-encoded buffer.
    ///
    /// # Errors
    /// Returns an error if the given buffer isn't a valid DER-encoded certificate.
    pub fn from_der(der: &[u8]) -> Result<Self, SigningCertificateParseError> {
        let cert = CapturedX509Certificate::from_der(der)?;
        Ok(Self { cert })
    }
}

/// Errors that may occur when parsing a signing key.
#[derive(Debug)]
pub enum SigningKeyParseError {
    Csr(rcgen::Error),
    Cms(x509_certificate::X509CertificateError),
}

impl std::fmt::Display for SigningKeyParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Csr(e) => write!(f, "failed to parse key for CSR signing: {e}"),
            Self::Cms(e) => write!(f, "failed to parse key for CMS signing: {e}"),
        }
    }
}

impl std::error::Error for SigningKeyParseError {}

impl From<rcgen::Error> for SigningKeyParseError {
    fn from(value: rcgen::Error) -> Self {
        Self::Csr(value)
    }
}

impl From<x509_certificate::X509CertificateError> for SigningKeyParseError {
    fn from(value: x509_certificate::X509CertificateError) -> Self {
        Self::Cms(value)
    }
}

/// Errors that may occur when parsing a signing certificate.
#[derive(Debug)]
pub struct SigningCertificateParseError(x509_certificate::X509CertificateError);

impl std::fmt::Display for SigningCertificateParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "failed to parse certificate: {}", self.0)
    }
}

impl std::error::Error for SigningCertificateParseError {}

impl From<x509_certificate::X509CertificateError> for SigningCertificateParseError {
    fn from(value: x509_certificate::X509CertificateError) -> Self {
        Self(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXAMPLE_RSA_CERT_PEM: &str = include_str!("../test/example.rsa.pem.cert");
    const EXAMPLE_RSA_CERT_DER: &[u8] = include_bytes!("../test/example.rsa.der.cert");
    const EXAMPLE_EC_KEY_PEM: &str = include_str!("../test/example.ec.pem.key");
    const EXAMPLE_EC_KEY_DER: &[u8] = include_bytes!("../test/example.ec.der.key");

    impl SigningKey {
        pub(crate) fn new_testing_key() -> Self {
            Self::from_pem(EXAMPLE_EC_KEY_PEM).unwrap()
        }
    }

    impl SigningCertificate {
        pub(crate) fn new_testing_cert() -> Self {
            Self::from_pem(EXAMPLE_RSA_CERT_PEM).unwrap()
        }
    }

    #[test]
    fn test_example_idempotency() {
        let once = SigningKey::new_testing_key();
        let twice = SigningKey::new_testing_key();
        assert_eq!(
            once.key_rcgen.serialized_der(),
            twice.key_rcgen.serialized_der()
        );

        let once = SigningCertificate::new_testing_cert();
        let twice = SigningCertificate::new_testing_cert();
        assert_eq!(
            once.cert.encode_der().unwrap(),
            twice.cert.encode_der().unwrap()
        );
    }

    #[test]
    fn test_signing_key_from_pem() {
        SigningKey::from_pem(EXAMPLE_EC_KEY_PEM).unwrap();
        assert!(SigningKey::from_pem("invalid").is_err());
    }

    #[test]
    fn test_signing_key_from_der() {
        SigningKey::from_der(EXAMPLE_EC_KEY_DER).unwrap();
        assert!(SigningKey::from_der(b"invalid").is_err());
    }

    #[test]
    fn test_certificate_from_pem() {
        SigningCertificate::from_pem(EXAMPLE_RSA_CERT_PEM).unwrap();
        assert!(SigningCertificate::from_pem("invalid").is_err());
    }

    #[test]
    fn test_certificate_from_der() {
        SigningCertificate::from_der(EXAMPLE_RSA_CERT_DER).unwrap();
        assert!(SigningCertificate::from_der(b"invalid").is_err());
    }
}
