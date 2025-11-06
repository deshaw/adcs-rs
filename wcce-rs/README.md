# `wcce-rs`

![Rust](https://github.com/deshaw/adcs-rs/workflows/Rust/badge.svg)
[![Crate](https://img.shields.io/crates/v/wcce-rs.svg)](https://crates.io/crates/wcce-rs)

`wcce-rs` is a Rust implementation of the [MS-WCCE] certificate enrollment protocol:

> Specifies the Windows Client Certificate Enrollment Protocol, which consists
> of a set of DCOM interfaces that enable clients to request various services
> from a certification authority (CA). These services enable X.509 (as
> specified in X509) digital certificate enrollment, issuance, revocation,
> and property retrieval.

## Introduction

From "[What is Active Directory Certificate Services?](https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/active-directory-certificate-services-overview)":

> Active Directory Certificate Services (AD CS) is a Windows Server role for issuing and managing public key infrastructure (PKI) certificates used in secure communication and authentication protocols.

Programmatically interacting with AD CS can be useful for automation—for example, to automate the enrollment and renewal of certificates.
These interactions are facilitated by protocols published and maintained by Microsoft. `adcs-rs` implements two of these protocols in Rust:

- MS-WCCE (this crate): Windows Client Certificate Enrollment Protocol
- MS-WSTEP: WS-Trust X.509v3 Token Enrollment Extensions Protocol

These protocols—as well as the `adcs-rs` crates that implement them—are composable.
For example, if the Certificate Enrollment Web Service (CES) has been set up, certificate enrollment may occur over HTTPS with the following method:

- MS-WCCE (this crate) is used to create certificate requests
- MS-WSTEP is used to send these certificate requests, query enrollment status, and retrieve enrolled certificates

```rust ignore
use wcce_rs::{
    attributes::EnrollmentNameValuePair,
    cms::{CmsCertificateRequest, CmsCertificateRequestBuildError},
    extensions::CertificateTemplate,
    pkcs10::{CertificateRequest, CertificateRequestBuildError, ExtendedKeyUsage, KeyUsage},
    signing::{SigningCertificate, SigningKey},
};
use wstep_rs::{
    request::{WstepRequest, WstepRequestSerializationError},
    response::{WstepResponse, WstepResponseError},
};

// ...

// Create a PKCS #10 certificate signing request (CSR)
let csr = CertificateRequest::builder()
    .add_key_usage(KeyUsage::DigitalSignature)
    .add_extended_key_usage(ExtendedKeyUsage::ClientAuth)
    .add_extended_key_usage(ExtendedKeyUsage::SmartCardLogon)
    .add_extension(&CertificateTemplate {
        template_oid,
        major_version,
        minor_version,
    })
    .build(&csr_signing_key)?;

// Wrap the CSR in a cryptographic message syntax (CMS) certificate request to add additional request parameters
let cms = CmsCertificateRequest::builder()
    .add_signed_name_value_pair(&EnrollmentNameValuePair::RequesterName {
        domain_account: &requester_name,
    })
    .build(&csr, &csr_signing_key, &csr_signing_cert)?;

/// Submit the CMS CSR over HTTP using SOAP
let soap = WstepRequest::new_issue_x509v3(
    &cms,
    &format!("urn:uuid:{}", &Uuid::new_v4()),
    Some(&adcs_ces_uri),
    None,
)
.serialize_request()?;

let request = http_client
    .post(&adcs_ces_uri)
    .header(CONTENT_TYPE, WstepRequest::SOAP_CONTENT_TYPE)
    .body(soap)
    .build()?;

// ...

let parsed_response = WstepResponse::new_from_soap_xml_str(&response_body)?;
match parsed_response.requested_token() {
    // Do something with the requested security token (certificate)
    Ok(token) => todo!(),
    // Inspect the fault returned by the server
    Err(fault) => todo!(),
}
```

## Request Formats

MS-WCCE defines four certificate request formats: PKCS #10, CMS, CMC and Netscape.
Request format support for this library is detailed below:

| Request Format      | Support | Notes                                         |
| ------------------- | ------- | --------------------------------------------- |
| PKCS #10            | ✔       | Uses custom MS-WCCE extensions and attributes |
| CMS                 | ✔       | Uses an inner PKCS #10 request                |
| CMC                 |         |                                               |
| Netscape KEYGEN Tag |         |                                               |

[MS-WCCE]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/446a0fca-7f27-4436-965d-191635518466

## Usage

Add `wcce-rs` to your dependencies in Cargo.toml. This crate comes with no additional features to enable:

```toml
[dependencies]
wcce-rs = "0.1.3"
```

## History

This library was developed by the [D. E. Shaw group](https://www.deshaw.com/) for secure, high-performance infrastructure engineering.

<p align="center">
    <a href="https://www.deshaw.com">
       <img src="https://www.deshaw.com/assets/logos/blue_logo_417x125.png" alt="D. E. Shaw Logo" height="75" >
    </a>
</p>

## License

This project is released under a [BSD-3-Clause license](LICENSE.txt).

We love contributions! Before you can contribute, please sign and submit this [Contributor License Agreement (CLA)](https://www.deshaw.com/oss/cla).
This CLA is in place to protect all users of this project.
