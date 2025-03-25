use wstep_rs::request::WstepRequest;

use pretty_assertions::assert_eq;

#[test]
fn test_protocol_example_standard_certificate_request() {
    let expected = include_str!("data/standard_certificate_client_request.xml");
    let pkcs7_cms = include_str!("data/standard_certificate_client_request.cms");
    let actual = WstepRequest::new_issue_x509v3(
        pkcs7_cms,
        "urn:uuid:b5d1a601-5091-4a7d-b34b-5204c18b5919",
        None,
        Some(WstepRequest::REPLY_TO_ANONYMOUS),
    )
    .serialize_request()
    .unwrap();
    assert_eq!(expected, actual);
}

#[test]
fn test_protocol_example_key_exchange_token_request() {
    let expected = include_str!("data/key_exchange_token_client_request.xml");
    let actual = WstepRequest::new_key_exchange_token(
        "urn:uuid:c2884a79-b943-45c6-ac02-7256071de309",
        WstepRequest::REPLY_TO_ANONYMOUS,
    )
    .serialize_request()
    .unwrap();
    assert_eq!(expected, actual);
}

#[test]
fn test_protocol_example_retrieve_previously_pended_certificate_request() {
    let expected = include_str!("data/retrieve_pended_certificate_request.xml");
    let actual = WstepRequest::new_query_token_status(
        "65",
        "urn:uuid:ce330bb2-0ca2-473b-a29a-19e9264666ff",
        WstepRequest::REPLY_TO_ANONYMOUS,
    )
    .serialize_request()
    .unwrap();
    assert_eq!(expected, actual);
}

#[test]
fn test_protocol_example_client_renewal_request() {
    let expected = include_str!("data/renewal_client_request.xml");
    let pkcs7_cms = include_str!("data/renewal_client_request.cms");
    let actual = WstepRequest::new_issue_x509v3(
        pkcs7_cms,
        "urn:uuid:b0a9b388-2581-451d-8c03-270d4ffe2928",
        None,
        Some("http://www.w3.org/2005/08/addressing/anonymous"),
    )
    .serialize_request()
    .unwrap();
    assert_eq!(expected, actual);
}
