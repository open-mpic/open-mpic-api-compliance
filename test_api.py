#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import argparse
import asyncio
from open_multi_perspective_issuance_corroboration_ap_iv_2_spec_client import Client
from open_multi_perspective_issuance_corroboration_ap_iv_2_spec_client.models import (
    DCVResponse,
    DCVParams,
    CAAParams,
    CAAResponse,
    CaaCheckParameters,
    CheckType,
    CaaCheckParametersCertificateType,
    AcmeDNS01ValidationParameters,
    AcmeHTTP01ValidationParameters,
    ValidationMethod,
    WebsiteChangeValidationParameters,
    DNSChangeValidationParameters,
    DNSChangeValidationParametersDnsRecordType,
    BaseDNSChangeValidationParameters,
    IpAddressValidationParameters,
    IpAddressValidationParametersDnsRecordType,
)
from open_multi_perspective_issuance_corroboration_ap_iv_2_spec_client.api.default import post_mpic
from open_multi_perspective_issuance_corroboration_ap_iv_2_spec_client.types import Response
from pprint import pp
import pytest

pytest_plugins = ("pytest_asyncio",)

API_URL = "http://localhost:8000/mpic-coordinator"


def parse_args():
    parser = argparse.ArgumentParser(prog="MPIC API Testing", description="Tests deployed MPIC API.")
    parser.add_argument("-u", "--url", default="http://localhost:8000/mpic-coordinator", help="The base API URL.")
    return parser.parse_args()


class TestDeployedMpicApi:
    # @classmethod
    # def setup_class(self):
    #    self.client = Client(base_url=API_URL)

    @pytest.mark.asyncio
    async def test_api_should_return_200_and_passed_corroboration_given_successful_caa_check(self):
        async with Client(base_url=API_URL) as client:
            request = CAAParams(domain_or_ip_target="example.com", check_type=CheckType.CAA)
            caa_response: Response[CAAResponse] = await post_mpic.asyncio_detailed(client=client, body=request)

            assert caa_response.status_code == 200
            assert caa_response.parsed.is_valid == True

        # fmt: off

    @pytest.mark.parametrize(
        "domain_or_ip_target, purpose_of_test, is_wildcard_domain",
        [
            ("empty.basic.caatestsuite.com", 'Tests handling of 0 issue ";"', False),
            ("deny.basic.caatestsuite.com", 'Tests handling of 0 issue "caatestsuite.com"', False),
            (
                "uppercase-deny.basic.caatestsuite.com",
                'Tests handling of uppercase issue tag (0 ISSUE "caatestsuite.com")',
                False,
            ),
            (
                "mixedcase-deny.basic.caatestsuite.com",
                'Tests handling of mixed case issue tag (0 IsSuE "caatestsuite.com")',
                False,
            ),
            (
                "big.basic.caatestsuite.com",
                'Tests handling of gigantic (1001) CAA record set (0 issue "caatestsuite.com")',
                False,
            ),
            (
                "critical1.basic.caatestsuite.com",
                'Tests handling of unknown critical property (128 caatestsuitedummyproperty "test")',
                False,
            ),
            (
                "critical2.basic.caatestsuite.com",
                "Tests handling of unknown critical property with another flag (130)",
                False,
            ),
            (
                "sub1.deny.basic.caatestsuite.com",
                "Tests basic tree climbing when CAA record is at parent domain",
                False,
            ),
            (
                "sub2.sub1.deny.basic.caatestsuite.com",
                "Tests tree climbing when CAA record is at grandparent domain",
                False,
            ),
            ("deny.basic.caatestsuite.com", "Tests handling of issue property for a wildcard domain", True),
            ("deny-wild.basic.caatestsuite.com", "Tests handling of issuewild for a wildcard domain", True),
            (
                "cname-deny.basic.caatestsuite.com",
                "Tests handling of CNAME, where CAA record is at CNAME target",
                False,
            ),
            (
                "cname-cname-deny.basic.caatestsuite.com",
                "Tests handling of CNAME chain, where CAA record is at ultimate target",
                False,
            ),
            (
                "sub1.cname-deny.basic.caatestsuite.com",
                "Tests handling of CNAME, where parent is CNAME and CAA record is at target",
                False,
            ),
            (
                "deny.permit.basic.caatestsuite.com",
                "Tests rejection when parent name contains a permissible CAA record set",
                False,
            ),
            ("ipv6only.caatestsuite.com", "Tests handling of record at IPv6-only authoritative name server", False),
            # ('expired.caatestsuite-dnssec.com', 'Tests rejection when expired DNSSEC signatures', False), # DNSSEC SHOULD be enabled in production but is not a current requirement for MPIC
            # ('missing.caatestsuite-dnssec.com', 'Tests rejection when missing DNSSEC signatures', False), # DNSSEC SHOULD be enabled in production but is not a current requirement for MPIC
            (
                "blackhole.caatestsuite-dnssec.com",
                "Tests rejection when DNSSEC chain goes to non-responsive server",
                False,
            ),
            (
                "servfail.caatestsuite-dnssec.com",
                "Tests rejection when DNSSEC chain goes to server returning SERVFAIL",
                False,
            ),
            (
                "refused.caatestsuite-dnssec.com",
                "Tests rejection when DNSSEC chain goes to server returning REFUSED",
                False,
            ),
            ("xss.caatestsuite.com", "Tests rejection when issue property has HTML and JS", False),
        ],
    )
    # fmt: on
    @pytest.mark.asyncio
    async def test_api_should_return_is_valid_false_for_all_tests_in_do_not_issue_caa_test_suite(
        self, domain_or_ip_target, purpose_of_test, is_wildcard_domain
    ):
        async with Client(base_url=API_URL) as client:
            print(f"Running test for {domain_or_ip_target} ({purpose_of_test})")
            if is_wildcard_domain:
                domain_or_ip_target = "*." + domain_or_ip_target
            request = CAAParams(
                domain_or_ip_target=domain_or_ip_target,
                check_type=CheckType.CAA,
                caa_check_parameters=CaaCheckParameters(caa_domains=["example.com"]),
            )
            caa_response: Response[CAAResponse] = await post_mpic.asyncio_detailed(client=client, body=request)
            assert caa_response.status_code == 200
            assert caa_response.parsed.is_valid is False

    # NOTE: Cases where there is no IPv6 connectivity.
    # This case is handled in a compliant manner as it is treated as a lookup failure.
    # The test for proper communication with an IPv6 nameserver can be enabled with the following additional parameter to the list below.
    # ('ipv6only.caatestsuite.com', 'Tests handling of record at IPv6-only authoritative name server', False),
    # fmt: off
    @pytest.mark.parametrize('domain_or_ip_target, purpose_of_test, is_wildcard_domain', [
        ('deny.basic.caatestsuite.com', 'Tests handling of 0 issue "caatestsuite.com"', False),
        ('uppercase-deny.basic.caatestsuite.com', 'Tests handling of uppercase issue tag (0 ISSUE "caatestsuite.com")', False),
        ('mixedcase-deny.basic.caatestsuite.com', 'Tests handling of mixed case issue tag (0 IsSuE "caatestsuite.com")', False),
        ('big.basic.caatestsuite.com', 'Tests handling of gigantic (1001) CAA record set (0 issue "caatestsuite.com")', False),
        ('sub1.deny.basic.caatestsuite.com', 'Tests basic tree climbing when CAA record is at parent domain', False),
        ('sub2.sub1.deny.basic.caatestsuite.com', 'Tests tree climbing when CAA record is at grandparent domain', False),
        ('deny.basic.caatestsuite.com', 'Tests handling of issue property for a wildcard domain', True),
        ('deny-wild.basic.caatestsuite.com', 'Tests handling of issuewild for a wildcard domain', True),
        ('cname-deny.basic.caatestsuite.com', 'Tests handling of CNAME, where CAA record is at CNAME target', False),
        ('cname-cname-deny.basic.caatestsuite.com', 'Tests handling of CNAME chain, where CAA record is at ultimate target', False),
        ('sub1.cname-deny.basic.caatestsuite.com', 'Tests handling of CNAME, where parent is CNAME and CAA record is at target', False),
        ('permit.basic.caatestsuite.com', 'Tests acceptance when name contains a permissible CAA record set', False),
        ('deny.permit.basic.caatestsuite.com', 'Tests acceptance on a CAA record set', False),
    ])
    # fmt: on
    @pytest.mark.asyncio
    async def test_api_should_return_is_valid_true_for_valid_tests_in_caa_test_suite_when_caa_domain_is_caatestsuite_com(
        self, domain_or_ip_target, purpose_of_test, is_wildcard_domain
    ):
        async with Client(base_url=API_URL) as client:
            print(f"Running test for {domain_or_ip_target} ({purpose_of_test})")
            if is_wildcard_domain:
                domain_or_ip_target = "*." + domain_or_ip_target
            request = CAAParams(
                domain_or_ip_target=domain_or_ip_target,
                check_type=CheckType.CAA,
                caa_check_parameters=CaaCheckParameters(
                    certificate_type=CaaCheckParametersCertificateType.TLS_SERVER, caa_domains=["caatestsuite.com", "example.com"]
                ),
            )
            caa_response: Response[CAAResponse] = await post_mpic.asyncio_detailed(client=client, body=request)
            assert caa_response.status_code == 200
            assert caa_response.parsed.is_valid is True
    

    # fmt: off
    @pytest.mark.parametrize('domain_or_ip_target, caa_domain_list, is_valid, purpose_of_test', [
        ('smime-standard.integration-testing.open-mpic.org', ["example-ca.example.com"], True, 'standard valid smime CAA'),
        ('contact-phone-caa.integration-testing.open-mpic.org', ["example-ca.example.com"], True, 'smime CAA not found' ),
        ('dns-phone-txt.integration-testing.open-mpic.org', ["example-ca.example.com"], True, 'smime: no CAA found' ),
        ('smime-with-issue.integration-testing.open-mpic.org', ["example-ca2.example.com"], True, 'smime and issue CAA' ),
        
        ('smime-standard.integration-testing.open-mpic.org', ["example-ca1.example.com"], False, 'standard invalid smime CAA'),
        ('smime-with-issue.integration-testing.open-mpic.org', ["example-ca1.example.com"], False, 'smime and issue CAA invalid: issue tag match but not issuemail' ),
        
    ])
    # fmt: on
    @pytest.mark.asyncio
    async def test_api_should_return_200_for_smime_tests(
        self, domain_or_ip_target, caa_domain_list, is_valid, purpose_of_test
    ):
        async with Client(base_url=API_URL) as client:
            print(f"Running test for {domain_or_ip_target} ({purpose_of_test})")
            request = CAAParams(
                domain_or_ip_target=domain_or_ip_target,
                check_type=CheckType.CAA,
                caa_check_parameters=CaaCheckParameters(
                    certificate_type=CaaCheckParametersCertificateType.S_MIME, caa_domains=caa_domain_list
                ),
            )
            caa_response: Response[CAAResponse] = await post_mpic.asyncio_detailed(client=client, body=request)
            pp(caa_response.parsed)
            assert caa_response.status_code == 200
            assert caa_response.parsed.is_valid == is_valid
    

    # fmt: off
    @pytest.mark.parametrize('domain_or_ip_target, purpose_of_test', [
        ('dns-01.integration-testing.open-mpic.org', 'Standard proper dns-01 test'),
        ('dns-01-multi.integration-testing.open-mpic.org', 'Proper dns-01 test with multiple TXT records'),
        ('dns-01-cname.integration-testing.open-mpic.org', 'Proper dns-01 test with CNAME')
    ])
    # fmt: on
    @pytest.mark.asyncio
    async def test_api_should_return_200_given_valid_dns_01_validation(self, domain_or_ip_target, purpose_of_test):
        print(f"Running test for {domain_or_ip_target} ({purpose_of_test})")
        async with Client(base_url=API_URL) as client:
            request = DCVParams(
                domain_or_ip_target=domain_or_ip_target,
                check_type=CheckType.DCV,
                dcv_check_parameters=AcmeDNS01ValidationParameters(
                    key_authorization_hash="7FwkJPsKf-TH54wu4eiIFA3nhzYaevsL7953ihy-tpo",
                    validation_method=ValidationMethod.ACME_DNS_01
                ),
            )

            response: Response[DCVResponse] = await post_mpic.asyncio_detailed(client=client, body=request)
            assert response.status_code == 200
            assert response.parsed.is_valid is True
    
    
    # fmt: off
    @pytest.mark.parametrize('domain_or_ip_target, purpose_of_test', [
        ('dns-01-leading-whitespace.integration-testing.open-mpic.org', 'leading whitespace'),
        ('dns-01-trailing-whitespace.integration-testing.open-mpic.org', 'trailing'),
        ('dns-01-nxdomain.integration-testing.open-mpic.org', 'NXDOMAIN')
    ])
    # fmt: on
    @pytest.mark.asyncio
    async def test_api_should_return_200_is_valid_false_given_invalid_dns_01_validation(
        self, domain_or_ip_target, purpose_of_test
    ):
        print(f"Running test for {domain_or_ip_target} ({purpose_of_test})")
        async with Client(base_url=API_URL) as client:
            request = DCVParams(
                domain_or_ip_target=domain_or_ip_target,
                check_type=CheckType.DCV,
                dcv_check_parameters=AcmeDNS01ValidationParameters(
                    key_authorization_hash="7FwkJPsKf-TH54wu4eiIFA3nhzYaevsL7953ihy-tpo",
                    validation_method=ValidationMethod.ACME_DNS_01
                ),
            )
            response: Response[DCVResponse] = await post_mpic.asyncio_detailed(client=client, body=request)
            assert response.status_code == 200
            assert response.parsed.is_valid is False


    # fmt: off
    @pytest.mark.parametrize('domain_or_ip_target, purpose_of_test, token, key_authorization', [
        ('integration-testing.open-mpic.org', 'Standard http-01 test', "evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA", "evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA.NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"),
        ('integration-testing.open-mpic.org', 'Redirect 302 http-01 test', "evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oB", "evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA.NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs")
    ])
    # fmt: on
    @pytest.mark.asyncio
    async def test_api_should_return_200_given_valid_http_01_validation(
        self, domain_or_ip_target, purpose_of_test, token, key_authorization
    ):
        print(f"Running test for {domain_or_ip_target} ({purpose_of_test})")
        async with Client(base_url=API_URL) as client:
            request = DCVParams(
                domain_or_ip_target=domain_or_ip_target,
                check_type=CheckType.DCV,
                dcv_check_parameters=AcmeHTTP01ValidationParameters(
                    key_authorization=key_authorization,
                    token=token, 
                    validation_method=ValidationMethod.ACME_HTTP_01
                    )
            )
            pp(request.to_dict())
            response: Response[DCVResponse] = await post_mpic.asyncio_detailed(client=client, body=request)
            assert response.status_code == 200
            #pp(response.content)
            assert response.parsed.is_valid is True

    # fmt: off
    @pytest.mark.parametrize('domain_or_ip_target, purpose_of_test, token, key_authorization', [
        ('integration-testing.open-mpic.org', 'Failed http-01 test', "evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA", "evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA.NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9XZ"),
        ('integration-testing.open-mpic.org', 'Failed 302 http-01 test', "evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oB", "evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA.NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9XZ"),
        ('integration-testing.open-mpic.org', '404 token', "evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oZ", "evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA.NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9XZ"),
        ('integration-testing.open-mpic.org', 'Failed http-01, bad redirect', "evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oC", "evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA.NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"),
    ])
    # fmt: on
    @pytest.mark.asyncio
    async def test_api_should_return_200_is_valid_false_given_invalid_http_01_validation(
        self, domain_or_ip_target, purpose_of_test, token, key_authorization
    ):
        print(f"Running test for {domain_or_ip_target} ({purpose_of_test})")
        async with Client(base_url=API_URL) as client:
            request = DCVParams(
                domain_or_ip_target=domain_or_ip_target,
                check_type=CheckType.DCV,
                dcv_check_parameters=AcmeHTTP01ValidationParameters(
                    key_authorization=key_authorization,
                    token=token, 
                    validation_method=ValidationMethod.ACME_HTTP_01
                    )
            )
            pp(request.to_dict())
            response: Response[DCVResponse] = await post_mpic.asyncio_detailed(client=client, body=request)
            assert response.status_code == 200
            #pp(response.content)
            assert response.parsed.is_valid is False

    # fmt: off
    @pytest.mark.parametrize('domain_or_ip_target, purpose_of_test, http_token_path, challenge_value', [
        ('integration-testing.open-mpic.org', 'Valid website change v2 challenge', 'validation-doc.txt', 'test-validation'),
        ('integration-testing.open-mpic.org', 'Valid 302 website change v2 challenge', 'validation-doc-redirect.txt', "test-validation-redirect")
    ])
    # fmt: on
    @pytest.mark.asyncio
    async def test_api_should_return_200_given_valid_website_change_validation(
        self, domain_or_ip_target, purpose_of_test, http_token_path, challenge_value
    ):
        print(f"Running test for {domain_or_ip_target} ({purpose_of_test})")
        async with Client(base_url=API_URL) as client:
            request = DCVParams(
                domain_or_ip_target=domain_or_ip_target,
                check_type=CheckType.DCV,
                dcv_check_parameters=WebsiteChangeValidationParameters(
                    http_token_path=http_token_path, challenge_value=challenge_value,
                    validation_method=ValidationMethod.WEBSITE_CHANGE
                ),
            )
            pp(request.to_dict())
            response: Response[DCVResponse] = await post_mpic.asyncio_detailed(client=client, body=request)
            assert response.status_code == 200
            #pp(response.content)
            assert response.parsed.is_valid is True

    # fmt: off
    @pytest.mark.parametrize('domain_or_ip_target, purpose_of_test, http_token_path, challenge_value', [
        ('integration-testing.open-mpic.org', 'Website change v2 challenge bad port redirect', 'validation-doc-bad-port-redirect.txt', 'test-validation-redirect')
    ])
    # fmt: on
    @pytest.mark.asyncio
    async def test_api_should_return_200_is_valid_false_given_invalid_website_change_validation(
        self, domain_or_ip_target, purpose_of_test, http_token_path, challenge_value
    ):
        print(f"Running test for {domain_or_ip_target} ({purpose_of_test})")
        async with Client(base_url=API_URL) as client:
            request = DCVParams(
                domain_or_ip_target=domain_or_ip_target,
                check_type=CheckType.DCV,
                dcv_check_parameters=WebsiteChangeValidationParameters(
                    http_token_path=http_token_path, challenge_value=challenge_value,
                    validation_method=ValidationMethod.WEBSITE_CHANGE
                ),
            )
            pp(request.to_dict())
            response: Response[DCVResponse] = await post_mpic.asyncio_detailed(client=client, body=request)
            assert response.status_code == 200
            #pp(response.content)
            assert response.parsed.is_valid is False


    # fmt: off
    @pytest.mark.parametrize('domain_or_ip_target, dns_record_type, challenge_value, purpose_of_test', [
        ('dns-change-txt.integration-testing.open-mpic.org', DNSChangeValidationParametersDnsRecordType.TXT, "1234567890abcdefg.", 'standard TXT dns change'),
        ('dns-change-cname.integration-testing.open-mpic.org', DNSChangeValidationParametersDnsRecordType.CNAME, "1234567890abcdefg.", 'standard CNAME dns change'),
        ('dns-change-caa.integration-testing.open-mpic.org', DNSChangeValidationParametersDnsRecordType.CAA, '1234567890abcdefg.', 'standard CAA dns change'),
    ])
    # fmt: on
    @pytest.mark.asyncio
    async def test_api_should_return_200_given_valid_dns_change_validation(
        self, domain_or_ip_target, dns_record_type, challenge_value, purpose_of_test
    ):
        print(f"Running test for {domain_or_ip_target} ({purpose_of_test})")
        async with Client(base_url=API_URL) as client:
            request = DCVParams(
                domain_or_ip_target=domain_or_ip_target,
                check_type=CheckType.DCV,
                dcv_check_parameters=DNSChangeValidationParameters(
                    challenge_value=challenge_value, dns_record_type=dns_record_type, dns_name_prefix="",
                    validation_method=ValidationMethod.DNS_CHANGE
                ),
            )
            pp(request.to_dict())
            response: Response[DCVResponse] = await post_mpic.asyncio_detailed(client=client, body=request)
            assert response.status_code == 200
            #pp(response.content)
            assert response.parsed.is_valid is True


    # fmt: off
    @pytest.mark.parametrize('domain_or_ip_target, challenge_value, purpose_of_test', [
        ('dns-phone-txt.integration-testing.open-mpic.org', "+1-123-456-7890", 'standard TXT contact phone'),
        ('dns-phone-cname-txt.integration-testing.open-mpic.org', "+1-123-456-7890", 'CNAME TXT contact phone'),
    ])
    # fmt: on
    @pytest.mark.asyncio
    async def test_api_should_return_200_given_valid_contact_phone_txt_validation(
        self, domain_or_ip_target, challenge_value, purpose_of_test
    ):
        print(f"Running test for {domain_or_ip_target} ({purpose_of_test})")
        async with Client(base_url=API_URL) as client:
            request = DCVParams(
                domain_or_ip_target=domain_or_ip_target,
                check_type=CheckType.DCV,
                dcv_check_parameters=BaseDNSChangeValidationParameters(
                    challenge_value=challenge_value,
                    validation_method=ValidationMethod.CONTACT_PHONE_TXT
                ),
            )
            pp(request.to_dict())
            response: Response[DCVResponse] = await post_mpic.asyncio_detailed(client=client, body=request)
            assert response.status_code == 200
            #pp(response.content)
            assert response.parsed.is_valid is True

    # fmt: off
    @pytest.mark.parametrize('domain_or_ip_target, challenge_value, purpose_of_test', [
        ('dns-phone-txt.integration-testing.open-mpic.org', "+1-123-456-7891", 'standard invalid TXT contact phone'),
        ('dns-phone-cname-txt.integration-testing.open-mpic.org', "+1-123-456-7891", 'CNAME invalid TXT contact phone'),
        ('dns-phone-txt-whitespace.integration-testing.open-mpic.org', "+1-123-456-7890", 'CNAME invalid TXT contact phone'),
    ])
    # fmt: on
    @pytest.mark.asyncio
    async def test_api_should_return_200_is_valid_false_given_invalid_contact_phone_txt_validation(
        self, domain_or_ip_target, challenge_value, purpose_of_test
    ):
        print(f"Running test for {domain_or_ip_target} ({purpose_of_test})")
        async with Client(base_url=API_URL) as client:
            request = DCVParams(
                domain_or_ip_target=domain_or_ip_target,
                check_type=CheckType.DCV,
                dcv_check_parameters=BaseDNSChangeValidationParameters(
                    challenge_value=challenge_value,
                    validation_method=ValidationMethod.CONTACT_PHONE_TXT
                ),
            )
            pp(request.to_dict())
            response: Response[DCVResponse] = await post_mpic.asyncio_detailed(client=client, body=request)
            assert response.status_code == 200
            #pp(response.content)
            assert response.parsed.is_valid is False


    # fmt: off
    @pytest.mark.parametrize('domain_or_ip_target, challenge_value, purpose_of_test', [
        ('dns-email-txt.integration-testing.open-mpic.org', "testadmin.email.txt@example.com", 'standard TXT contact email'),
        ('dns-email-txt-cname.integration-testing.open-mpic.org', "testadmin.cname.target@example.com", 'CNAME TXT contact email'),
        
    ])
    # fmt: on
    @pytest.mark.asyncio
    async def test_api_should_return_200_given_valid_contact_email_txt_validation(
        self, domain_or_ip_target, challenge_value, purpose_of_test
    ):
        print(f"Running test for {domain_or_ip_target} ({purpose_of_test})")
        async with Client(base_url=API_URL) as client:
            request = DCVParams(
                domain_or_ip_target=domain_or_ip_target,
                check_type=CheckType.DCV,
                dcv_check_parameters=BaseDNSChangeValidationParameters(
                    challenge_value=challenge_value,
                    validation_method=ValidationMethod.CONTACT_EMAIL_TXT
                ),
            )
            pp(request.to_dict())
            response: Response[DCVResponse] = await post_mpic.asyncio_detailed(client=client, body=request)
            assert response.status_code == 200
            #pp(response.content)
            assert response.parsed.is_valid is True

    # fmt: off
    @pytest.mark.parametrize('domain_or_ip_target, challenge_value, purpose_of_test', [
        ('dns-email-txt.integration-testing.open-mpic.org', "testadmin2.email.txt@example.com", 'standard invalid TXT contact email'),
        ('dns-email-txt-cname.integration-testing.open-mpic.org', "testadmin2.cname.target@example.com", 'CNAME invalid TXT contact email'),
        ('dns-email-txt-whitespace.integration-testing.open-mpic.org', "testadmin.email.txt.whitespace@example.com", 'whitespace invalid TXT contact email'),
        ('dns-email-txt-null-char.integration-testing.open-mpic.org', "testadmin.email.txt.null.char@example.com", 'null char invalid TXT contact email'),
        ('dns-email-txt-junk.integration-testing.open-mpic.org', "testadmin.email.txt.junk@example.com", 'junk invalid TXT contact email'),
        
    ])
    # fmt: on
    @pytest.mark.asyncio
    async def test_api_should_return_200_is_valid_false_given_invalid_contact_email_txt_validation(
        self, domain_or_ip_target, challenge_value, purpose_of_test
    ):
        print(f"Running test for {domain_or_ip_target} ({purpose_of_test})")
        async with Client(base_url=API_URL) as client:
            request = DCVParams(
                domain_or_ip_target=domain_or_ip_target,
                check_type=CheckType.DCV,
                dcv_check_parameters=BaseDNSChangeValidationParameters(
                    challenge_value=challenge_value,
                    validation_method=ValidationMethod.CONTACT_EMAIL_TXT
                ),
            )
            pp(request.to_dict())
            response: Response[DCVResponse] = await post_mpic.asyncio_detailed(client=client, body=request)
            assert response.status_code == 200
            #pp(response.content)
            assert response.parsed.is_valid is False


    # fmt: off
    @pytest.mark.parametrize('domain_or_ip_target, challenge_value, purpose_of_test', [
        ('contact-email-caa.integration-testing.open-mpic.org', "caa.contactemail@example.com", 'standard CAA contact email'),
        ('contact-email-caa-critical.integration-testing.open-mpic.org', "caa.contactemail@example.com", 'critical CAA contact email'),
        ('sub.contact-email-caa.integration-testing.open-mpic.org', "caa.contactemail@example.com", 'subdomain CAA contact email'),
        ('nxsub.sub.contact-email-caa.integration-testing.open-mpic.org', "caa.contactemail@example.com", 'nxdomain below subdomain CAA contact email'),
        ('contact-email-caa-cname.integration-testing.open-mpic.org', "caa.contactemail@example.com", 'CNAME CAA contact email'),
        ('contact-email-caa-multi.integration-testing.open-mpic.org', "caa1.contactemail@example.com", 'multi-record CAA contact email'),
        
    ])
    # fmt: on
    @pytest.mark.asyncio
    async def test_api_should_return_200_is_valid_true_given_valid_contact_email_caa_validation(
        self, domain_or_ip_target, challenge_value, purpose_of_test
    ):
        print(f"Running test for {domain_or_ip_target} ({purpose_of_test})")
        async with Client(base_url=API_URL) as client:
            request = DCVParams(
                domain_or_ip_target=domain_or_ip_target,
                check_type=CheckType.DCV,
                dcv_check_parameters=BaseDNSChangeValidationParameters(
                    challenge_value=challenge_value,
                    validation_method=ValidationMethod.CONTACT_EMAIL_CAA
                ),
            )
            pp(request.to_dict())
            response: Response[DCVResponse] = await post_mpic.asyncio_detailed(client=client, body=request)
            assert response.status_code == 200
            #pp(response.content)
            assert response.parsed.is_valid is True

    # fmt: off
    @pytest.mark.parametrize('domain_or_ip_target, challenge_value, purpose_of_test', [
        ('contact-email-caa.integration-testing.open-mpic.org', "caa.contactemail1@example.com", 'standard invalid CAA contact email'),
        ('contact-email-caa-critical.integration-testing.open-mpic.org', "caa.contactemail1@example.com", 'critical invalid CAA contact email'),
        ('sub.contact-email-caa.integration-testing.open-mpic.org', "caa.contactemail1@example.com", 'subdomain invalid CAA contact email'),
        ('nxsub.sub.contact-email-caa.integration-testing.open-mpic.org', "caa.contactemail1@example.com", 'nxdomain below subdomain invalid CAA contact email'),
        ('contact-email-caa-cname.integration-testing.open-mpic.org', "caa.contactemail1@example.com", 'CNAME invalid CAA contact email'),
        ('contact-email-caa-multi.integration-testing.open-mpic.org', "caa1.contactemail1@example.com", 'multi-record invalid CAA contact email'),
        ('contact-email-caa-whitespace.integration-testing.open-mpic.org', "caa.contactemail@example.com", 'whitespace invalid CAA contact email'),
        ('contact-email-caa-null.integration-testing.open-mpic.org', "caa.contactemail@example.com", 'null char invalid CAA contact email'),
        ('contact-email-no-record-set.integration-testing.open-mpic.org', "caa.contactemail@example.com", 'no record set invalid CAA contact email'),
        
    ])
    # fmt: on
    @pytest.mark.asyncio
    async def test_api_should_return_200_is_valid_false_given_invalid_contact_email_caa_validation(
        self, domain_or_ip_target, challenge_value, purpose_of_test
    ):
        print(f"Running test for {domain_or_ip_target} ({purpose_of_test})")
        async with Client(base_url=API_URL) as client:
            request = DCVParams(
                domain_or_ip_target=domain_or_ip_target,
                check_type=CheckType.DCV,
                dcv_check_parameters=BaseDNSChangeValidationParameters(
                    challenge_value=challenge_value,
                    validation_method=ValidationMethod.CONTACT_EMAIL_CAA
                ),
            )
            pp(request.to_dict())
            response: Response[DCVResponse] = await post_mpic.asyncio_detailed(client=client, body=request)
            assert response.status_code == 200
            #pp(response.content)
            assert response.parsed.is_valid is False



    # fmt: off
    @pytest.mark.parametrize('domain_or_ip_target, challenge_value, is_valid, purpose_of_test', [
        ('contact-phone-caa.integration-testing.open-mpic.org', "+1-123-456-7890", True, 'standard valid CAA contact phone'),
        ('contact-phone-caa-multi.integration-testing.open-mpic.org', "+1-123-456-7890", True, 'multi valid CAA contact phone'),
        ('contact-phone-caa-critical.integration-testing.open-mpic.org', "+1-123-456-7890", True, 'critical valid CAA contact phone'),
        ('contact-phone-caa.integration-testing.open-mpic.org', "+1-123-456-7891", False, 'standard invalid CAA contact phone'),
        ('contact-phone-caa-multi.integration-testing.open-mpic.org', "+1-123-456-7891", False, 'multi invalid CAA contact phone'),
        ('contact-phone-caa-critical.integration-testing.open-mpic.org', "+1-123-456-7891", False, 'critical invalid CAA contact phone'),
        ('contact-phone-caa-whitespace.integration-testing.open-mpic.org', "+1-123-456-7890", False, 'whitespace invalid CAA contact phone'),
        
    ])
    # fmt: on
    @pytest.mark.asyncio
    async def test_api_should_return_200_given_contact_phone_caa_validation(
        self, domain_or_ip_target, challenge_value, is_valid, purpose_of_test
    ):
        print(f"Running test for {domain_or_ip_target} ({purpose_of_test})")
        async with Client(base_url=API_URL) as client:
            request = DCVParams(
                domain_or_ip_target=domain_or_ip_target,
                check_type=CheckType.DCV,
                dcv_check_parameters=BaseDNSChangeValidationParameters(
                    challenge_value=challenge_value,
                    validation_method=ValidationMethod.CONTACT_PHONE_CAA
                ),
            )
            pp(request.to_dict())
            response: Response[DCVResponse] = await post_mpic.asyncio_detailed(client=client, body=request)
            assert response.status_code == 200
            #pp(response.content)
            assert response.parsed.is_valid == is_valid

    # fmt: off
    @pytest.mark.parametrize('domain_or_ip_target, challenge_value, record_type, is_valid, purpose_of_test', [
        ('ip-address.integration-testing.open-mpic.org', "1.2.3.4", IpAddressValidationParametersDnsRecordType.A, True, 'standard valid IPv4'),
        ('ip-address-cname.integration-testing.open-mpic.org', "1.2.3.4", IpAddressValidationParametersDnsRecordType.A, True, 'valid cname IPv4'),
        ('ip-address-multi.integration-testing.open-mpic.org', "1.2.3.4", IpAddressValidationParametersDnsRecordType.A, True, 'valid multi IPv4'),
        ('ip-address-v6.integration-testing.open-mpic.org', "2001:4860:4860::8888", IpAddressValidationParametersDnsRecordType.AAAA, True, 'standard valid IPv6'),
        ('ip-address-v6.integration-testing.open-mpic.org', "2001:4860:4860:0:00:000:0000:8888", IpAddressValidationParametersDnsRecordType.AAAA, True, 'expanded notation valid IPv6'),
        
        ('ip-address.integration-testing.open-mpic.org', "1.2.3.5", IpAddressValidationParametersDnsRecordType.A, False, 'standard invalid IPv4'),
        ('ip-address-nxdomain.integration-testing.open-mpic.org', "1.2.3.4", IpAddressValidationParametersDnsRecordType.A, False, 'nxdomain invalid IPv4'),
        ('contact-phone-caa.integration-testing.open-mpic.org', "1.2.3.4",  IpAddressValidationParametersDnsRecordType.A, False, 'no record type invalid IPv4'),
        ('ip-address-v6.integration-testing.open-mpic.org', "2001:4860:4860::8889", IpAddressValidationParametersDnsRecordType.AAAA, False, 'standard invalid IPv6'),
        ('ip-address-v6.integration-testing.open-mpic.org', "2001:4860:4860:0:0:0:0:0:8889", IpAddressValidationParametersDnsRecordType.AAAA, False, 'bad IPv6 notation too many octets'),
        ('ip-address-v6.integration-testing.open-mpic.org', "2001:4860:4860:0:0:0:00000:8889", IpAddressValidationParametersDnsRecordType.AAAA, False, 'bad IPv6 notation too many zeros'),
        ('ip-address.integration-testing.open-mpic.org', "1.2.3.4", IpAddressValidationParametersDnsRecordType.AAAA, False, 'wrong address type v4 in AAAA'),
    ])
    # fmt: on
    @pytest.mark.asyncio
    async def test_api_should_return_200_given_ip_address_validation(
        self, domain_or_ip_target, challenge_value, record_type: IpAddressValidationParametersDnsRecordType, is_valid, purpose_of_test
    ):
        print(f"Running test for {domain_or_ip_target} ({purpose_of_test})")
        async with Client(base_url=API_URL) as client:
            request = DCVParams(
                domain_or_ip_target=domain_or_ip_target,
                check_type=CheckType.DCV,
                dcv_check_parameters=IpAddressValidationParameters(
                    challenge_value=challenge_value,
                    validation_method=ValidationMethod.IP_ADDRESS,
                    dns_record_type=record_type
                ),
            )
            pp(request.to_dict())
            response: Response[DCVResponse] = await post_mpic.asyncio_detailed(client=client, body=request)
            assert response.status_code == 200
            #pp(response.content)
            assert response.parsed.is_valid == is_valid


async def main(args):
    print(f'Running basic test. Run "pytest" to run the full test file.')
    print(args.url)
    client = Client(base_url=args.url)
    async with client as client:
        body = CAAParams(
            domain_or_ip_target="example.com",
            check_type=CheckType.CAA,
            caa_check_parameters=CaaCheckParameters(certificate_type=CaaCheckParametersCertificateType.TLS_SERVER),
        )
        caa_response: Response[CAAResponse] = await post_mpic.asyncio_detailed(client=client, body=body)

        print(caa_response.status_code)
        # print(caa_response.content)
        pp(caa_response.parsed)


if __name__ == "__main__":
    asyncio.run(main(parse_args()))
