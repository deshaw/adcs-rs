use std::{
    fs::File,
    io::BufReader,
    path::{Path, PathBuf},
    str::FromStr,
    sync::Arc,
};

use anyhow::Context;
use clap::Parser;
use reqwest::header::CONTENT_TYPE;
use rustls::{
    ClientConfig, RootCertStore,
    pki_types::{CertificateDer, PrivateKeyDer},
};

use uuid::Uuid;
use wcce_rs::{pkcs10::CertificateRequest, signing::SigningKey};
use wstep_rs::{request::WstepRequest, response::WstepResponse};

#[derive(Parser, Debug)]
#[command(
    name = "ADCS-RS Simple Issue Request Example",
    author = "Lukas Velikov <lukas.velikov@deshaw.com>",
    about = "Make a simple certificate request using ADCS-RS",
    arg_required_else_help = true,
    version
)]
struct Cli {
    /// Path to a private key to sign the CSR with.
    #[arg(long = "csr-key")]
    csr_key_path: PathBuf,

    /// Certificate Enrollment Web Service (CES) endpoint (e.g., `https://adcs.domain.org/MyCESInstance/service.svc/CES`)
    #[arg(long)]
    adcs_ces_uri: String,

    /// OID of the certificate template to issue against
    #[arg(long = "template-oid", value_parser = clap::value_parser!(OidOpt))]
    template_oid: OidOpt,

    /// Major version of the certificate template to issue against
    #[arg(long = "template-major-version", default_value_t = 0)]
    template_major_version: u32,

    /// Minor version of the certificate template to issue against
    #[arg(long = "template-minor-version", default_value_t = 0)]
    template_minor_version: u32,

    /// Path to a PEM-encoded TLS client authentication certificate
    #[arg(long = "tls-cert")]
    tls_cert_path: PathBuf,

    /// Path to a PEM-encoded TLS client authentication key
    #[arg(long = "tls-key")]
    tls_key_path: PathBuf,

    /// Path to PEM-encoded trusted CAs for TLS
    #[arg(long = "tls-ca")]
    tls_ca_path: PathBuf,
}

fn main() -> anyhow::Result<()> {
    // Parse the command line arguments
    let cli = Cli::parse();

    // Read the signing key from the specified path
    let csr_signing_key = read_signing_key(cli.csr_key_path)?;

    // Create an HTTP client with a Rustls TLS backend
    let http_client =
        http_client_with_rustls_tls(cli.tls_cert_path, cli.tls_key_path, cli.tls_ca_path)?;

    // Create a certificate signing request (CSR) that conforms to MS-WCCE
    let csr = CertificateRequest::builder()
        // Specify the certificate template to use for the request
        .add_extension(&wcce_rs::extensions::CertificateTemplate {
            template_oid: cli.template_oid.as_ref(),
            major_version: Some(cli.template_major_version),
            minor_version: Some(cli.template_minor_version),
        })
        .build(&csr_signing_key)?
        .to_pem()?;

    // Create an MS-WSTEP SOAP request to issue a certificate
    let soap = WstepRequest::new_issue_x509v3(
        // The MS-WSTEP request wraps an inner base64-encoded request
        // This is usually a PKCS #10 certificate signing request (CSR)
        // But it could also be a CMS certificate request that contains a CSR
        &csr,
        // Create a unique request ID for tracking purposes
        &format!("urn:uuid:{}", &Uuid::new_v4()),
        // This is an optional "to" field that specifies the AD CS Web Services CES endpoint
        // This is often required in practice, but not always
        Some(&cli.adcs_ces_uri),
        // This is a "reply to" field that specifies the endpoint to send the response to
        // This isn't required in practice, but MS-WSTEP supports it
        None,
    )
    .serialize_request()?;

    // Create an HTTP request to the AD CS Web Services CES endpoint
    let request = http_client
        .post(cli.adcs_ces_uri)
        .header(CONTENT_TYPE, WstepRequest::SOAP_CONTENT_TYPE)
        .body(soap)
        .build()?;
    let response = http_client.execute(request)?;

    // Output the response URL, status, and headers
    eprintln!("{response:#?}");

    // Attempt to parse the server response as an MS-WSTEP message
    let response_text = response.text()?;
    match WstepResponse::new_from_soap_xml_str(&response_text) {
        Ok(parsed_response) => println!("{parsed_response:#?}"),
        Err(parse_error) => {
            eprintln!("Failed to parse response:\n{parse_error:#?}");
            eprintln!("Response text:\n{response_text}");
        }
    }

    Ok(())
}

/// Create an HTTP client with a Rustls TLS backend using the given paths for the client certificate,
/// key, and CA certificates.
///
/// # Errors
/// Returns an error if the client certificate, key, or CA certificates cannot be read, or if the
/// HTTP client cannot be built.
fn http_client_with_rustls_tls<P: AsRef<Path>>(
    tls_cert_path: P,
    tls_key_path: P,
    tls_ca_path: P,
) -> anyhow::Result<reqwest::blocking::Client> {
    let tls_cert = read_certificates(tls_cert_path)?;
    let tls_key = read_private_key(tls_key_path)?;
    let (ca_store, _, _) = read_root_cert_store(tls_ca_path)?;
    let tls_config =
        ClientConfig::builder_with_provider(rustls::crypto::aws_lc_rs::default_provider().into())
            .with_safe_default_protocol_versions()?
            .with_root_certificates(ca_store)
            .with_client_auth_cert(tls_cert, tls_key)?;
    let http_client = reqwest::blocking::Client::builder()
        .use_preconfigured_tls(tls_config)
        .build()?;
    Ok(http_client)
}

/// Read the PEM-encoded private key at the given [`Path`] into a format usable by Rustls.
///
/// # Errors
/// Returns an error if the private key cannot be read.
fn read_private_key<P: AsRef<Path>>(path: P) -> anyhow::Result<PrivateKeyDer<'static>> {
    let file = File::open(&path)?;
    let mut reader = BufReader::new(file);
    let key = rustls_pemfile::private_key(&mut reader)?.context("failed to read private key")?;
    Ok(key)
}

/// Read the PEM-encoded private key at the given [`Path`] into a format usable by ADCS-RS.
///
/// # Errors
/// Returns an error if the private key cannot be read.
fn read_signing_key<P: AsRef<Path>>(key_path: P) -> anyhow::Result<SigningKey> {
    let key_der = read_private_key(key_path)?;
    Ok(SigningKey::from_der(key_der.secret_der())?)
}

/// Read the PEM-encoded trusted certificates at the given [`Path`] into a format usable by Rustls.
/// The number of successfully parsed and malformed certificates are also returned respectively.
///
/// # Errors
/// Returns an error if the certificates cannot be read.
fn read_root_cert_store<P: AsRef<Path>>(
    ca_cert_path: P,
) -> anyhow::Result<(Arc<RootCertStore>, usize, usize)> {
    let ca_certificates_der = read_certificates(ca_cert_path)?;
    let mut root_cert_store = rustls::RootCertStore::empty();
    let (num_added, num_unparsable) =
        root_cert_store.add_parsable_certificates(ca_certificates_der);
    Ok((Arc::new(root_cert_store), num_added, num_unparsable))
}

/// Read the PEM-encoded certificates at the given [`Path`] into a [`Vec`] of [`CertificateDer`].
///
/// # Errors
/// Returns an error if the certificates cannot be read.
fn read_certificates<P: AsRef<Path>>(path: P) -> anyhow::Result<Vec<CertificateDer<'static>>> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let certs = rustls_pemfile::certs(&mut reader).collect::<Result<_, _>>()?;
    Ok(certs)
}

/// Represents an OID.
#[derive(Debug, Clone)]
struct OidOpt(Vec<u64>);

impl AsRef<[u64]> for OidOpt {
    fn as_ref(&self) -> &[u64] {
        &self.0
    }
}

impl FromStr for OidOpt {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.split('.')
            .map(u64::from_str)
            .collect::<Result<Vec<u64>, _>>()
            .map(OidOpt)
            .map_err(|e| format!("{e}"))
    }
}
