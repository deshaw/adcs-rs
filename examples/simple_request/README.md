# ADCS-RS Example: Simple Request CLI

This ADCS-RS example illustrates a simple CLI for requesting certificates for a specified certificate template over HTTP.

## Requirements

Successfully running this example requires the following:

- Windows Server—this example was last run on Microsoft Windows Server 2025 (OS Build 26100.4349)
- [Active Directory Certificate Services (AD CS)](https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/active-directory-certificate-services-overview)
- [Certificate Enrollment Web Service (CES)](https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/configure-certificate-enrollment-web-service)
- [Certificate template](https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/certificate-template-concepts)
- Client authentication certificate issued from AD CS

The CLI exclusively supports enrollment requests for certificate templates where the 'Supply in the request' option is disabled and subject information is constructed from Active Directory attributes according to the template's Subject Name and Subject Alternative Name configuration tabs.

The following additional setup *may* be required:

### Enable Client Certificate Negotiation

Note the settings for your SSL certificate bindings with `netsh http show ssl`.
Take note of:

- `IP:port`
- `Certificate Hash`
- `Application ID`
- `Negotiate Client Certificate`

Additionally, take note of `DS Mapper Usage` if it's `Enabled`—enabling client certificate negotiation will disable this as a side effect.

In an elevated shell, enable client cert negotiation using netsh.exe (changing values as needed):

```powershell
PS C:\Windows\system32> netsh http update sslcert ipport=$ipPort certhash=$certHash appid=$appId clientcertnegotiation=enable
```

If `DS Mapper Usage` was enabled, run this instead:

```powershell
PS C:\Windows\system32> netsh http update sslcert ipport=$ipPort certhash=$certHash appid=$appId clientcertnegotiation=enable dsmapperusage=enable

SSL Certificate successfully updated

PS C:\Windows\system32> iisreset.exe
```

An error message of `The parameter is incorrect` indicates a shell that isn't elevated or an incorrect `netsh` invocation.

### Populate the `Client Authentication Issuers` Store

Add the certificate of your AD CS instance to the `Client Authentication Issuers` Store.
An intended side effect of this that the CA certificate will be sent as a hint to the client during certificate negotiation.
More information about this is available [here](https://learn.microsoft.com/en-us/windows-server/security/tls/what-s-new-in-tls-ssl-schannel-ssp-overview#BKMK_TrustedIssuers).

```powershell
PS C:\Windows\system32> Import-Certificate -FilePath $pathToCaCert -CertStoreLocation Cert:\LocalMachine\ClientAuthIssuer
```
### Enable Sending Trusted Issuer List for TLS Handshake

By default, Schannel will not send trusted CA names in TLS handshakes.
To enable this, set the following registry key:

```powershell
PS C:\Windows\system32> reg.exe ADD HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\SendTrustedIssuerList /v 1 /t REG_DWORD
```

## Usage

The example may be compiled and run with `cargo run --package`:

```console
$ cargo run --package simple_request -- --help
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.50s
     Running `target/debug/simple_request --help`

Make a simple certificate request using ADCS-RS

Usage: simple_request [OPTIONS] --csr-key <CSR_KEY_PATH> --adcs-ces-uri <ADCS_CES_URI> --template-oid <TEMPLATE_OID> --tls-cert <TLS_CERT_PATH> --tls-key <TLS_KEY_PATH> --tls-ca <TLS_CA_PATH>

Options:
      --csr-key <CSR_KEY_PATH>
          Path to a private key to sign the CSR with
      --adcs-ces-uri <ADCS_CES_URI>
          Certificate Enrollment Web Service (CES) endpoint (e.g., `https://adcs.domain.org/MyCESInstance/service.svc/CES`)
      --template-oid <TEMPLATE_OID>
          OID of the certificate template to issue against
      --template-major-version <TEMPLATE_MAJOR_VERSION>
          Major version of the certificate template to issue against [default: 0]
      --template-minor-version <TEMPLATE_MINOR_VERSION>
          Minor version of the certificate template to issue against [default: 0]
      --tls-cert <TLS_CERT_PATH>
          Path to a PEM-encoded TLS client authentication certificate
      --tls-key <TLS_KEY_PATH>
          Path to a PEM-encoded TLS client authentication key
      --tls-ca <TLS_CA_PATH>
          Path to PEM-encoded trusted CAs for TLS
  -h, --help
          Print help
  -V, --version
          Print version
```

A truncated example is shown below:

```console
cargo run -p simple_request -- \
    --csr-key csr_key.key \
    --adcs-ces-uri https://adcs-test.example.org/example-ca-1_CES_Certificate/service.svc/CES \
    --template-oid "2.999.1.2.3" \
    --tls-cert tls_cert.crt \
    --tls-key tls_key.key \
    --tls-ca trusted_ca_list.crt


Response {
    url: "https://adcs-test.example.org/example-ca-1_CES_Certificate/service.svc/CES",
    status: 200,
    headers: {
        "content-type": "application/soap+xml; charset=utf-8",
        "server": "Microsoft-IIS/10.0",
        "x-powered-by": "ASP.NET",
        "date": "Tue, 08 Jul 2025 23:24:46 GMT",
        "content-length": "9038",
    },
}

WstepResponse {
    envelope: ResponseEnvelope {
        xmlns_s: "http://www.w3.org/2003/05/soap-envelope",
        xmlns_a: "http://www.w3.org/2005/08/addressing",
        header: Header {
            action: Action {
                must_understand: MustUnderstand(
                    true,
                ),
                action_type: RequestSecurityTokenResponseCollection,
            },
            activity_id: Some(
                ActivityId {
                    correlation_id: "204b79e5-4f96-47c9-af24-02dab0585224",
                    xmlns: "http://schemas.microsoft.com/2004/09/ServiceModel/Diagnostics",
                    value: "00000000-0000-0000-0000-000000000000",
                },
            ),
            relates_to: Some(
                "urn:uuid:384247ba-de84-4903-bdff-5cb394b2b0cc",
            ),
            message_id: None,
            reply_to: None,
            to: None,
        },
        body: ResponseBody {
            value: Success(
                RequestSecurityTokenResponseCollection {
                    xmlns: "http://docs.oasis-open.org/ws-sx/ws-trust/200512",
                    request_security_token_response: RequestSecurityTokenResponse {
                        requested_security_token: BinarySecurityToken {
                            binary_security_token: BinarySecurityToken {
                                encoding_type: Base64Binary,
                                value_type: X509v3,
                                xmlns: "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd",
                                value: "MIIG(truncated)\r",
                            },
                        },
                        token_type: TokenType {
                            value: "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3",
                        },
                        binary_security_token: Some(
                            BinarySecurityToken {
                                encoding_type: Base64Binary,
                                value_type: Pkcs7,
                                xmlns: "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd",
                                value: "MIIM(truncated)\r",
                            },
                        ),
                        disposition_message: Some(
                            DispositionMessage {
                                lang: "en-US",
                                xmlns: "http://schemas.microsoft.com/windows/pki/2009/01/enrollment",
                                value: "Issued",
                            },
                        ),
                        request_id: Some(
                            RequestId {
                                value: Some(
                                    "29",
                                ),
                                xsi_nil: None,
                                xmlns: Some(
                                    "http://schemas.microsoft.com/windows/pki/2009/01/enrollment",
                                ),
                            },
                        ),
                    },
                },
            ),
        },
    },
}
```
