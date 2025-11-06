# `adcs-rs`

`adcs-rs` contains Rust crates for the [MS-WCCE] and [MS-WSTEP] protocols, which may be used to interact with Active Directory Certificate Services (AD CS).

Related projects include [certreq](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/certreq_1), Windows' certificate request utility, and [Certipy](https://github.com/ly4k/Certipy).

## Crates

The following protocols are supported.
Each protocol is implemented in its own crate:

| Crate                 | Protocol   | Description                                                                      |                                                                     |                                                                                             |
| --------------------- | ---------- | -------------------------------------------------------------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------------------------------- |
| [wcce-rs](wcce-rs/)   | [MS-WCCE]  | Rust implementation of the Windows Client Certificate Enrollment Protocol        | ![Rust](https://github.com/deshaw/adcs-rs/workflows/Rust/badge.svg) | [![Crate](https://img.shields.io/crates/v/wcce-rs.svg)](https://crates.io/crates/wcce-rs)   |
| [wstep-rs](wstep-rs/) | [MS-WSTEP] | Rust implementation of the WS-Trust X.509v3 Token Enrollment Extensions Protocol | ![Rust](https://github.com/deshaw/adcs-rs/workflows/Rust/badge.svg) | [![Crate](https://img.shields.io/crates/v/wstep-rs.svg)](https://crates.io/crates/wstep-rs) |

### Related Protocols

The following list of related protocols have not been implemented by `adcs-rs`.
This list is non-exhaustive:

| Protocol   | Description                                | Notes                            |
| ---------- | ------------------------------------------ | -------------------------------- |
| [MS-CAESO] | Certificate Autoenrollment System Overview | Superset of MS-WCCE and MS-WSTEP |
| [MS-CRTD]  | Certificate Templates Structure            |                                  |
| [MS-ICPR]  | ICertPassage Remote Protocol               | Subset of MS-WCCE                |
| [MS-XCEP]  | Certificate Enrollment Policy Protocol     |                                  |

## Introduction

From "[What is Active Directory Certificate Services?](https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/active-directory-certificate-services-overview)":

> Active Directory Certificate Services (AD CS) is a Windows Server role for issuing and managing public key infrastructure (PKI) certificates used in secure communication and authentication protocols.

Programmatically interacting with AD CS can be useful for automation—for example, to automate the enrollment and renewal of certificates.
These interactions are facilitated by protocols published and maintained by Microsoft. `adcs-rs` implements two of these protocols in Rust:

- MS-WCCE: Windows Client Certificate Enrollment Protocol
- MS-WSTEP: WS-Trust X.509v3 Token Enrollment Extensions Protocol

These protocols—as well as the `adcs-rs` crates that implement them—are composable.
For example, if the Certificate Enrollment Web Service (CES) has been set up, certificate enrollment may occur over HTTPS with the following method:

- MS-WCCE is used to create certificate requests
- MS-WSTEP is used to send these certificate requests, query enrollment status, and retrieve enrolled certificates

```rust
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



## Usage

For [MS-WCCE] support, add `wcce-rs` to your dependencies in Cargo.toml. This crate comes with no additional features to enable:

```toml
[dependencies]
wcce-rs = "0.1.3"
```

For [MS-WSTEP] support, add `wstep-rs` to your dependencies in Cargo.toml. This crate comes with no additional features to enable:

```toml
[dependencies]
wstep-rs = "0.1.3"
```

[MS-WCCE]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/446a0fca-7f27-4436-965d-191635518466
[MS-WSTEP]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wstep/4766a85d-0d18-4fa1-a51f-e5cb98b752ea
[MS-CAESO]: https://download.microsoft.com/download/C/8/8/C8862966-5948-444D-87BD-07B976ADA28C/%5BMS-CAESO%5D.pdf
[MS-CRTD]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-crtd/4c6950e4-1dc2-4ae3-98c3-b8919bb73822
[MS-ICPR]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-icpr/9b8ed605-6b00-41d1-9a2a-9897e40678fc
[MS-XCEP]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-xcep/08ec4475-32c2-457d-8c27-5a176660a210

## History

These libraries were developed by the [D. E. Shaw group](https://www.deshaw.com/) for secure, high-performance infrastructure engineering.

<p align="center">
    <a href="https://www.deshaw.com">
       <img src="https://www.deshaw.com/assets/logos/blue_logo_417x125.png" alt="D. E. Shaw Logo" height="75" >
    </a>
</p>

## License

This project is released under a [BSD-3-Clause license](LICENSE.txt).

We love contributions! Before you can contribute, please sign and submit this [Contributor License Agreement (CLA)](https://www.deshaw.com/oss/cla).
This CLA is in place to protect all users of this project.
