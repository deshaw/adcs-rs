use wstep_rs::{
    common::{ActivityId, BinarySecurityToken, RequestId},
    response::{
        BinaryResponse, CertificateEnrollmentWsDetail, ErrorCode, Fault, FaultCode, FaultCodeValue,
        FaultDetail, FaultReason, FaultReasonText, FaultSubcode, FaultSubcodeValue, FaultType,
        InvalidRequest, WstepResponse,
    },
};

use pretty_assertions::assert_eq;

#[test]
fn test_protocol_example_standard_certificate_response() {
    let response = include_str!("data/standard_certificate_server_response.xml");
    let bst_inner = include_str!("data/standard_certificate_server_response_bst_inner.cms");
    let bst_outer = include_str!("data/standard_certificate_server_response_bst_outer.cms");
    let expected = WstepResponse::new_issued_x509v3(
        ActivityId::new(
            "95427c83-902c-48db-9529-f61cc1d8c035",
            "a0f231a3-ccf2-4b9c-99a6-bc353a59b5d0",
        ),
        "urn:uuid:b5d1a601-5091-4a7d-b34b-5204c18b5919",
        "61",
        BinarySecurityToken::new_pkcs7_base64(bst_outer),
        BinarySecurityToken::new_x509v3_base64(bst_inner),
    );
    let actual = WstepResponse::new_from_soap_xml_str(response).unwrap();
    assert_eq!(expected, actual);
}

#[test]
fn test_protocol_example_key_exchange_token_server_response() {
    let response = include_str!("data/key_exchange_token_server_response.xml");
    let cms = include_str!("data/key_exchange_token_server_response.cms");
    let actual = WstepResponse::new_from_soap_xml_str(response).unwrap();
    let expected = WstepResponse::new_key_exchange_token(
        ActivityId::new(
            "17f6073c-c108-4268-9ce4-713ed86894b6",
            "45f6782a-fb93-4a48-b0bb-a21496ba1f3c",
        ),
        "urn:uuid:c2884a79-b943-45c6-ac02-7256071de309",
        BinarySecurityToken::new_x509v3_base64(cms),
    );
    assert_eq!(expected, actual);
}

#[test]
fn test_protocol_example_fault_server_response() {
    let response = include_str!("data/fault_server_response.xml");
    let actual = WstepResponse::new_from_soap_xml_str(response).unwrap();
    let expected = WstepResponse::new_fault(
        FaultType::DispatcherFault,
        ActivityId::new(
            "eda7e63d-0c42-455d-9c4f-47ab85803a50",
            "4f0e4425-4883-41c1-b704-771135d18f84",
        ),
        "urn:uuid:ce330bb2-0ca2-473b-a29a-19e9264666ff",
        Fault {
            code: FaultCode {
                value: FaultCodeValue { value: "s:Receiver".into() },
                subcode: Some(FaultSubcode {
                    value: FaultSubcodeValue::new("a:InternalServiceFault"),
                }),
            },
            reason: FaultReason {
                text: FaultReasonText::new(Some("The server was unable to process the request due to an internal error. For more information about the error, either turn on IncludeExceptionDetailInFaults (either from ServiceBehaviorAttribute or from the <<serviceDebug>> configuration behavior) on the server in order to send the exception information back to the client, or turn on tracing as per the Microsoft .NET Framework 3.0 SDK documentation and inspect the server trace logs."))
            },
            detail: None,
        },
    );
    assert_eq!(expected, actual);
}

#[test]
fn test_protocol_example_renewal_server_response() {
    let response = include_str!("data/renewal_server_response.xml");
    let bst_inner = include_str!("data/renewal_server_response_bst_inner.cms");
    let bst_outer = include_str!("data/renewal_server_response_bst_outer.cms");

    let actual = WstepResponse::new_from_soap_xml_str(response).unwrap();
    let expected = WstepResponse::new_issued_x509v3(
        ActivityId::new(
            "0a9f1849-8211-489c-a2b7-6a07ed1e6832",
            "b17bfb40-747b-477a-a83c-175624e401aa",
        ),
        "urn:uuid:b0a9b388-2581-451d-8c03-270d4ffe2928",
        "63",
        BinarySecurityToken::new_pkcs7_base64(bst_outer),
        BinarySecurityToken::new_x509v3_base64(bst_inner),
    );
    assert_eq!(expected, actual);
}

#[test]
fn test_fault_bad_template_version_server_repsonse() {
    let response = include_str!("data/fault_bad_template_version_server_response.xml");
    let actual = WstepResponse::new_from_soap_xml_str(response).unwrap();
    let expected = WstepResponse::new_fault(
        FaultType::DetailFault,
        ActivityId::new(
            "95427c83-902c-48db-9529-f61cc1d8c035",
            "9d0799d0-a193-4445-8f39-4d5617c2e071",
        ),
        "urn:uuid:925fcd3d-c008-4caf-b390-3cd13b21f90f",
        Fault {
            code: FaultCode {
                value: FaultCodeValue {
                    value: "s:Receiver".into(),
                },
                subcode: None,
            },
            reason: FaultReason {
                text: FaultReasonText::new(Some("Denied by Policy Module")),
            },
            detail: Some(FaultDetail {
                certificate_enrollment_ws_detail: CertificateEnrollmentWsDetail::new(
                    BinaryResponse::new("VkVoV2NsbFlUV2RqTWtZMVkzbENiMkZSUFQwPQ=="),
                    ErrorCode::BadTemplateVersion,
                    InvalidRequest::new(true),
                    RequestId {
                        value: Some("368".into()),
                        xsi_nil: None,
                        xmlns: None,
                    },
                ),
            }),
        },
    );
    assert_eq!(expected, actual);
}

#[test]
fn test_fault_restricted_officer_server_response() {
    let response = include_str!("data/fault_restricted_officer_server_response.xml");
    let actual = WstepResponse::new_from_soap_xml_str(response).unwrap();
    let expected = WstepResponse::new_fault(
        FaultType::DetailFault,
        ActivityId::new(
            "95427c83-902c-48db-9529-f61cc1d8c035",
            "3d686545-fa56-4353-a949-c3683458f9a7",
        ),
        "urn:uuid:95d2dbd8-2caa-4fe3-9bbb-e55d53286290",
        Fault {
            code: FaultCode {
                value: FaultCodeValue {
                    value: "s:Receiver".into(),
                },
                subcode: None,
            },
            reason: FaultReason {
                text: FaultReasonText::new(None),
            },
            detail: Some(FaultDetail {
                certificate_enrollment_ws_detail: CertificateEnrollmentWsDetail::new(
                    BinaryResponse::new("VkVoV2NsbFlUV2RqTWtZMVkzbENiMkZSUFQwPQ=="),
                    ErrorCode::RestrictedOfficer,
                    InvalidRequest::new(true),
                    RequestId {
                        value: Some("28".into()),
                        xsi_nil: None,
                        xmlns: None,
                    },
                ),
            }),
        },
    );
    assert_eq!(expected, actual);
}

#[test]
fn test_fault_address_filter_mismatch_server_response() {
    let response = include_str!("data/fault_address_filter_mismatch_server_response.xml");
    let actual = WstepResponse::new_from_soap_xml_str(response).unwrap();
    let expected = WstepResponse::new_fault(
        FaultType::SoapFault,
        ActivityId::new(
            "00000000-0000-0000-0000-000000000000",
            "7c83bdf3-57f7-49ff-b182-cfd5d1ea3312",
        ),
        "urn:uuid:67cbc6c5-4536-493f-9923-0c5fa4c90942",
        Fault {
            code: FaultCode {
                value: FaultCodeValue {
                    value: "s:Sender".into(),
                },
                subcode: Some(FaultSubcode {
                    value: FaultSubcodeValue{ xmlns_a: None, value: "a:DestinationUnreachable".into() },
                }),
            },
            reason: FaultReason { text: FaultReasonText::new(Some("The message with To '' cannot be processed at the receiver, due to an AddressFilter mismatch at the EndpointDispatcher.  Check that the sender and receiver's EndpointAddresses agree.")) },
            detail: None,
        },
    );
    assert_eq!(expected, actual);
}
