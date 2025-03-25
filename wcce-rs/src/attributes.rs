use yasna::{construct_der, DERWriterSet};

use crate::pkcs10::Attribute;

/// Structs that implement this trait may be encoded as an MS-WCCE
/// attribute. [Section 1.1] of MS-WCCE loosely defines an attribute:
///
/// > A characteristic of some object or entity, typically encoded as a
/// > name/value pair.
///
/// In practice, MS-WCCE attributes are encoded similarly to attributes as
/// defined by [PKCS #10] and [RFC 5280].
///
/// [Section 1.1]: <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/719b890d-62e6-4322-b9b1-1f34d11535b4>
/// [PKCS #10]: <https://datatracker.ietf.org/doc/html/rfc2986#section-4>
/// [RFC 5280]: <https://datatracker.ietf.org/doc/html/rfc5280#appendix-A.1>
pub(crate) trait WcceAttribute {
    /// The object identifier (OID) associated with this attribute.
    const ATTRIBUTE_OID: &'static [u64];

    /// Rules for DER-encoding the value of this attribute.
    /// All MS-WCCE attribute values are encoded within an ASN.1 SET.
    fn values(&self, writer: &mut DERWriterSet);
}

impl<T> Attribute for T
where
    T: WcceAttribute,
{
    fn oid(&self) -> &'static [u64] {
        Self::ATTRIBUTE_OID
    }

    fn values(&self) -> Vec<u8> {
        construct_der(|writer| {
            writer.write_set(|writer| {
                self.values(writer);
            });
        })
    }
}

/// Used when creating a request to renew an existing certificate.
/// For example, when renewing your own certificate, this attribute contains
/// the certificate being renewed.
///
/// From [section 2.2.2.7.3] of MS-WCCE:
///
/// > Internal Name: szOID_RENEWAL_CERTIFICATE.
/// >
/// > Description: This attribute MUST be the certificate associated with the
/// > private key used to sign a request to renew an existing certificate.
///
/// [section 2.2.2.7.3]: <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/de82f94d-3f25-4963-8173-18d9681ea3e9>
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RenewalCertificate<'a> {
    pub certificate: &'a [u8],
}

impl WcceAttribute for RenewalCertificate<'_> {
    /// From [section 2.2.2.7.3] of MS-WCCE:
    ///
    /// > OID = 1.3.6.1.4.1.311.13.1.
    ///
    /// [section 2.2.2.7.3]: <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/de82f94d-3f25-4963-8173-18d9681ea3e9>
    const ATTRIBUTE_OID: &'static [u64] = &[1, 3, 6, 1, 4, 1, 311, 13, 1];

    /// From [section 2.2.2.7.3] of MS-WCCE:
    ///
    /// > Format: The value of the attribute MUST be the DER, as specified in
    /// > X.690, encoded certificate.
    ///
    /// [section 2.2.2.7.3]: <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/de82f94d-3f25-4963-8173-18d9681ea3e9>
    fn values(&self, writer: &mut DERWriterSet) {
        writer.next().write_der(self.certificate);
    }
}

/// Possible values for the validity period of an [`EnrollmentNameValuePair`],
/// as defined by [section 2.2.2.7.10] of MS-WCCE.
///
/// [section 2.2.2.7.10]: <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/92f07a54-2889-45e3-afd0-94b60daa80ec>
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ValidityPeriod {
    Seconds,
    Minutes,
    Hours,
    Days,
    Weeks,
    Months,
    Years,
}

impl ValidityPeriod {
    const fn value(self) -> &'static str {
        match self {
            Self::Seconds => "Seconds",
            Self::Minutes => "Minutes",
            Self::Hours => "Hours",
            Self::Days => "Days",
            Self::Weeks => "Weeks",
            Self::Months => "Months",
            Self::Years => "Years",
        }
    }
}

/// Certificate enrollment name-value pairs used by varying types of
/// certificate requests.
///
/// From [section 2.2.2.7.10] of MS-WCCE:
///
/// > OID = 1.3.6.1.4.1.311.13.2.1
/// >
/// > Internal Name: szOID_ENROLLMENT_NAME_VALUE_PAIR.
/// >
/// > Description: Additional attributes that SHOULD be used.
///
/// Enum variant descriptions have been transcribed into Markdown from [section
/// 2.2.2.7.10]. Links and stray section references have been removed.
///
/// [section 2.2.2.7.10]: <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/92f07a54-2889-45e3-afd0-94b60daa80ec>
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnrollmentNameValuePair<'a> {
    /// This attribute MUST be used along with a Netscape KEYGEN request.
    /// It MUST define the type of certificate that the client needs.
    CertType,

    /// The request OIDs for use in the `ExtendedKeyUsage` extension, as
    /// specified in [RFC 3280] section 4.2.1.13.
    ///
    /// [RFC 3280]: https://datatracker.ietf.org/doc/html/rfc3280
    CertificateUsage { oids: &'a str },

    /// The validity period of the request MUST be defined in two values:
    /// number and units. For example, number=3 and units=weeks means that the
    /// request is for a certificate that will be valid for 3 weeks.
    /// This value MUST define the units for the validity period.
    ValidityPeriod(ValidityPeriod),

    /// This value MUST define the number units used for the validity period.
    /// The units are defined in the `ValidityPeriod` attribute.
    ValidityPeriodUnits { count: &'a str },

    /// This value MUST define the exact request expiration time of the
    /// requested certificate in the format defined in section 3.3 of the
    /// [RFC 2616].
    ///
    /// [RFC 2616]: https://datatracker.ietf.org/doc/html/rfc2616
    ExpirationDate { date: &'a str },

    /// An Active Directory server FQDN.
    /// "CDC" stands for "certificate distribution center".
    Cdc { cdc_fqdn: &'a str },

    /// The requesting machine FQDN.
    /// "RMD" stands for "requesting machine domain".
    Rmd { rmd_fqdn: &'a str },

    /// This value MUST define the certificate template that was used by the
    /// client to construct the certificate request.
    CertificateTemplate { cn: &'a str },

    /// This value MUST contain a collection of one or more name-value pairs
    /// for the `SubjectAltName` extension. The format for the internal
    /// collection MUST be:
    ///
    /// `"name1=value1&name2=value"`.
    ///
    /// The supported names for this internal name-value collection are:
    ///
    /// - Guid
    /// - Email
    /// - FQDN
    /// - Dn
    /// - url
    /// - ipaddress
    /// - oid
    /// - upn
    /// - spn
    ///
    /// For all these names, the value MAY be any string.
    /// In addition to these names, the name MAY be any OID.
    /// If it is an OID, the value MUST be encoded as defined by MS-WCCE.
    San { collection: &'a str },

    /// This attribute MUST be passed only with a Netscape KEYGEN request
    /// format. The value of the attribute MUST be the challenge (password)
    /// string associated with the request.
    /// For specifications, see section 3.1.1.4.3.1.4.
    Challenge { challenge: &'a str },

    /// The identity of the user whose information MUST be used to construct
    /// the subject information of an issued certificate.
    /// It is used along with a ROBO for a different subject.
    ///
    /// Note: Unlike the other attributes, this attribute can be passed only
    /// within a request format and cannot be passed using the pwszAttributes
    /// parameter.
    RequesterName { domain_account: &'a str },

    /// The client requests that the server publish the issued certificate to
    /// the Universal Naming Convention (UNC) path that is specified in the
    /// value for this attribute.
    CertFile { unc_path: &'a str },

    /// The request ID of the request that is pending the attestation Challenge
    /// Response.
    RequestId { id: &'a str },

    /// A valid RDN string SHOULD be used to pass subject names for a
    /// certificate request generated by using the KEYGEN format on a Netscape
    /// browser.
    Other { name: &'static str, value: &'a str },
}

impl<'a> EnrollmentNameValuePair<'a> {
    /// OID for `enrollmentNameValuePair` (§2.2.2.7.10 `szENROLLMENT_NAME_VALUE_PAIR`).
    /// Equivalent of [`Self::ATTRIBUTE_OID`].
    pub(crate) const ATTRIBUTE_OID_STR: &'static str = "1.3.6.1.4.1.311.13.2.1";

    /// Get this name-value pair's name.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::CertType => "CertType",
            Self::CertificateUsage { oids: _ } => "CertificateUsage",
            Self::ValidityPeriod(_) => "ValidityPeriod",
            Self::ValidityPeriodUnits { count: _ } => "ValidityPeriodUnits",
            Self::ExpirationDate { date: _ } => "ExpirationDate",
            Self::Cdc { cdc_fqdn: _ } => "cdc",
            Self::Rmd { rmd_fqdn: _ } => "rmd",
            Self::CertificateTemplate { cn: _ } => "CertificateTemplate",
            Self::San { collection: _ } => "SAN",
            Self::Challenge { challenge: _ } => "challenge",
            Self::RequesterName { domain_account: _ } => "requestername",
            Self::CertFile { unc_path: _ } => "CertFile",
            Self::RequestId { id: _ } => "RequestId",
            Self::Other { name, value: _ } => name,
        }
    }

    /// Get this name-value pair's value.
    #[must_use]
    pub const fn value(&self) -> &'a str {
        match self {
            // There is only one permitted value for CertType
            Self::CertType => "server",
            Self::CertificateUsage { oids } => oids,
            Self::ValidityPeriod(period) => period.value(),
            Self::ValidityPeriodUnits { count } => count,
            Self::ExpirationDate { date } => date,
            Self::Cdc { cdc_fqdn } => cdc_fqdn,
            Self::Rmd { rmd_fqdn } => rmd_fqdn,
            Self::CertificateTemplate { cn } => cn,
            Self::San { collection } => collection,
            Self::Challenge { challenge } => challenge,
            Self::RequesterName { domain_account } => domain_account,
            Self::CertFile { unc_path } => unc_path,
            Self::RequestId { id } => id,
            Self::Other { name: _, value } => value,
        }
    }
}

impl WcceAttribute for EnrollmentNameValuePair<'_> {
    /// From [section 2.2.2.7.10] of MS-WCCE:
    ///
    /// > OID = 1.3.6.1.4.1.311.13.2.1
    ///
    /// [section 2.2.2.7.10]: <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/92f07a54-2889-45e3-afd0-94b60daa80ec>
    const ATTRIBUTE_OID: &'static [u64] = &[1, 3, 6, 1, 4, 1, 311, 13, 2, 1];

    /// From [section 2.2.2.7.10] of MS-WCCE:
    ///
    /// > Format: This attribute MUST be a collection of zero or more
    /// > name-value pairs. The following is the ASN.1 format.
    /// >
    /// > ```asn1
    /// > EnrollmentNameValuePairs ::= SEQUENCE OF EnrollmentNameValuePair
    /// > EnrollmentNameValuePair ::= SEQUENCE {
    /// >         name                BMPSTRING,
    /// >         value               BMPSTRING
    /// > }  --#public
    /// > ```
    ///
    /// [section 2.2.2.7.10]: <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/92f07a54-2889-45e3-afd0-94b60daa80ec>
    fn values(&self, writer: &mut DERWriterSet) {
        writer.next().write_sequence(|writer| {
            writer.next().write_bmp_string(self.name());
            writer.next().write_bmp_string(self.value());
        });
    }
}

/// [`RequestClientInfo`] is not defined by MS-WCCE.
/// However, it is included in PKCS #10 certificate requests generated by the
/// `certreq` command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestClientInfo<'a> {
    /// Machine name.
    pub machine: &'a str,
    /// Username in `NetBIOS` domain name\username format.
    pub user: &'a str,
    /// Name of the program generating the request (e.g. "certreq.exe").
    pub exe: &'a str,
    /// Integer version.
    pub version: u32,
}

impl WcceAttribute for RequestClientInfo<'_> {
    const ATTRIBUTE_OID: &'static [u64] = &[1, 3, 6, 1, 4, 1, 311, 21, 20];

    fn values(&self, writer: &mut DERWriterSet) {
        writer.next().write_sequence(|writer| {
            writer.next().write_u32(self.version);
            writer.next().write_utf8_string(self.machine);
            writer.next().write_utf8_string(self.user);
            writer.next().write_utf8_string(self.exe);
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_renewal_certificate_der() {
        #[rustfmt::skip]
        let expected: &[u8] = &[
            // SET with length 3
            0x31, 0x03,
            // Certificate DER data (3 bytes): SEQUENCE with length 1 containing NULL
            0x30, 0x01, 0x00,
        ];
        let actual = <RenewalCertificate as Attribute>::values(&RenewalCertificate {
            certificate: &[0x30, 0x01, 0x00],
        });
        assert_eq!(expected, actual);

        // Test with longer certificate (10 bytes)
        #[rustfmt::skip]
        let expected: &[u8] = &[
            // SET with length 10
            0x31, 0x0a,
            // Certificate DER data (10 bytes): SEQUENCE containing INTEGER and OCTET STRING
            0x30, 0x08, 0x02, 0x01, 0x01, 0x04, 0x03, 0x66, 0x6f, 0x6f,
        ];
        let actual = <RenewalCertificate as Attribute>::values(&RenewalCertificate {
            certificate: &[0x30, 0x08, 0x02, 0x01, 0x01, 0x04, 0x03, 0x66, 0x6f, 0x6f],
        });
        assert_eq!(expected, actual);
    }

    #[test]
    fn test_request_client_info_der() {
        #[rustfmt::skip]
        let expected: &[u8] = &[
            // SET with length 25
            0x31, 0x19,
            // SEQUENCE with length 23
            0x30, 0x17,
            // INTEGER 0 (version)
            0x02, 0x01, 0x00,
            // UTF8String "machine" (length 7)
            0x0c, 0x07, 0x6d, 0x61, 0x63, 0x68, 0x69, 0x6e, 0x65,
            // UTF8String "user" (length 4)
            0x0c, 0x04, 0x75, 0x73, 0x65, 0x72,
            // UTF8String "exe" (length 3)
            0x0c, 0x03, 0x65, 0x78, 0x65,
        ];
        let actual = <RequestClientInfo as Attribute>::values(&RequestClientInfo {
            machine: "machine",
            user: "user",
            exe: "exe",
            version: 0,
        });
        assert_eq!(expected, actual);

        #[rustfmt::skip]
        let expected: &[u8] = &[
            // SET with length 29
            0x31, 0x1d,
            // SEQUENCE with length 27
            0x30, 0x1b,
            // INTEGER u32::MAX (5-byte encoding)
            0x02, 0x05, 0x00, 0xff, 0xff, 0xff, 0xff,
            // UTF8String "machine" (length 7)
            0x0c, 0x07, 0x6d, 0x61, 0x63, 0x68, 0x69, 0x6e, 0x65,
            // UTF8String "user" (length 4)
            0x0c, 0x04, 0x75, 0x73, 0x65, 0x72,
            // UTF8String "exe" (length 3)
            0x0c, 0x03, 0x65, 0x78, 0x65,
        ];
        let actual = <RequestClientInfo as Attribute>::values(&RequestClientInfo {
            machine: "machine",
            user: "user",
            exe: "exe",
            version: u32::MAX,
        });
        assert_eq!(expected, actual);
    }

    #[test]
    fn test_enrollment_name_value_pair_der() {
        // Test CertType variant
        // Expected: SET containing SEQUENCE with two BMPSTRINGs
        #[rustfmt::skip]
        let expected: &[u8] = &[
            // SET with length 34
            0x31, 0x22,
            // SEQUENCE with length 32
            0x30, 0x20,
            // BMPSTRING with length 16 for "CertType" (8 chars * 2 bytes)
            0x1e, 0x10, 0x00, 0x43, 0x00, 0x65, 0x00, 0x72, 0x00, 0x74, 0x00, 0x54, 0x00, 0x79,
            0x00, 0x70, 0x00, 0x65,
            // BMPSTRING with length 12 for "server" (6 chars * 2 bytes)
            0x1e, 0x0c, 0x00, 0x73, 0x00, 0x65, 0x00, 0x72, 0x00, 0x76, 0x00, 0x65, 0x00, 0x72,
        ];
        let actual =
            <EnrollmentNameValuePair as Attribute>::values(&EnrollmentNameValuePair::CertType);
        assert_eq!(expected, actual);

        // Test CertificateTemplate variant with custom value
        #[rustfmt::skip]
        let expected: &[u8] = &[
            // SET with length 62
            0x31, 0x3e,
            // SEQUENCE with length 60
            0x30, 0x3c,
            // BMPSTRING with length 38 for "CertificateTemplate" (19 chars * 2 bytes)
            0x1e, 0x26, 0x00, 0x43, 0x00, 0x65, 0x00, 0x72, 0x00, 0x74, 0x00, 0x69, 0x00, 0x66,
            0x00, 0x69, 0x00, 0x63, 0x00, 0x61, 0x00, 0x74, 0x00, 0x65, 0x00, 0x54, 0x00, 0x65,
            0x00, 0x6d, 0x00, 0x70, 0x00, 0x6c, 0x00, 0x61, 0x00, 0x74, 0x00, 0x65,
            // BMPSTRING with length 18 for "WebServer" (9 chars * 2 bytes)
            0x1e, 0x12, 0x00, 0x57, 0x00, 0x65, 0x00, 0x62, 0x00, 0x53, 0x00, 0x65, 0x00, 0x72,
            0x00, 0x76, 0x00, 0x65, 0x00, 0x72,
        ];
        let actual = <EnrollmentNameValuePair as Attribute>::values(
            &EnrollmentNameValuePair::CertificateTemplate { cn: "WebServer" },
        );
        assert_eq!(expected, actual);

        // Test ValidityPeriod variant
        #[rustfmt::skip]
        let expected: &[u8] = &[
            // SET with length 42
            0x31, 0x2a,
            // SEQUENCE with length 40
            0x30, 0x28,
            // BMPSTRING with length 28 for "ValidityPeriod" (14 chars * 2 bytes)
            0x1e, 0x1c, 0x00, 0x56, 0x00, 0x61, 0x00, 0x6c, 0x00, 0x69, 0x00, 0x64, 0x00, 0x69,
            0x00, 0x74, 0x00, 0x79, 0x00, 0x50, 0x00, 0x65, 0x00, 0x72, 0x00, 0x69, 0x00, 0x6f,
            0x00, 0x64,
            // BMPSTRING with length 8 for "Days" (4 chars * 2 bytes)
            0x1e, 0x08, 0x00, 0x44, 0x00, 0x61, 0x00, 0x79, 0x00, 0x73,
        ];
        let actual = <EnrollmentNameValuePair as Attribute>::values(
            &EnrollmentNameValuePair::ValidityPeriod(ValidityPeriod::Days),
        );
        assert_eq!(expected, actual);
    }
}
