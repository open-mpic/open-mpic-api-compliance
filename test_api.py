#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import argparse
import asyncio
from open_multi_perspective_issuance_corroboration_ap_iv_2_spec_client import Client
from open_multi_perspective_issuance_corroboration_ap_iv_2_spec_client.models import CAAParams, CAAResponse, CaaCheckParameters, CheckType, CaaCheckParametersCertificateType
from open_multi_perspective_issuance_corroboration_ap_iv_2_spec_client.api.default import post_mpic
from open_multi_perspective_issuance_corroboration_ap_iv_2_spec_client.types import Response
from pprint import pp
import pytest

pytest_plugins = ('pytest_asyncio',)

API_URL = "http://localhost:8000/mpic-coordinator"

def parse_args():
    parser = argparse.ArgumentParser(prog='MPIC API Testing',
                    description='Tests deployed MPIC API.')
    parser.add_argument('-u', '--url', default="http://localhost:8000/mpic-coordinator", help='The base API URL.')
    return parser.parse_args()

class TestDeployedMpicApi:
    #@classmethod
    #def setup_class(self):
    #    self.client = Client(base_url=API_URL)
    
    @pytest.mark.asyncio
    async def test_api_should_return_200_and_passed_corroboration_given_successful_caa_check(self):
        async with Client(base_url=API_URL) as client:
            request = CAAParams(domain_or_ip_target="example.com", check_type=CheckType.CAA)
            caa_response: Response[CAAResponse] = await post_mpic.asyncio_detailed(client=client, body=request)
            
            assert caa_response.status_code == 200
            assert caa_response.parsed.is_valid == True
    

        # fmt: off
    @pytest.mark.parametrize('domain_or_ip_target, purpose_of_test, is_wildcard_domain', [
        ('empty.basic.caatestsuite.com', 'Tests handling of 0 issue ";"', False),
        ('deny.basic.caatestsuite.com', 'Tests handling of 0 issue "caatestsuite.com"', False),
        ('uppercase-deny.basic.caatestsuite.com', 'Tests handling of uppercase issue tag (0 ISSUE "caatestsuite.com")', False),
        ('mixedcase-deny.basic.caatestsuite.com', 'Tests handling of mixed case issue tag (0 IsSuE "caatestsuite.com")', False),
        ('big.basic.caatestsuite.com', 'Tests handling of gigantic (1001) CAA record set (0 issue "caatestsuite.com")', False),
        ('critical1.basic.caatestsuite.com', 'Tests handling of unknown critical property (128 caatestsuitedummyproperty "test")', False),
        ('critical2.basic.caatestsuite.com', 'Tests handling of unknown critical property with another flag (130)', False),
        ('sub1.deny.basic.caatestsuite.com', 'Tests basic tree climbing when CAA record is at parent domain', False),
        ('sub2.sub1.deny.basic.caatestsuite.com', 'Tests tree climbing when CAA record is at grandparent domain', False),
        ('deny.basic.caatestsuite.com', 'Tests handling of issue property for a wildcard domain', True),
        ('deny-wild.basic.caatestsuite.com', 'Tests handling of issuewild for a wildcard domain', True),
        ('cname-deny.basic.caatestsuite.com', 'Tests handling of CNAME, where CAA record is at CNAME target', False),
        ('cname-cname-deny.basic.caatestsuite.com', 'Tests handling of CNAME chain, where CAA record is at ultimate target', False),
        ('sub1.cname-deny.basic.caatestsuite.com', 'Tests handling of CNAME, where parent is CNAME and CAA record is at target', False),
        ('deny.permit.basic.caatestsuite.com', 'Tests rejection when parent name contains a permissible CAA record set', False),
        ('ipv6only.caatestsuite.com', 'Tests handling of record at IPv6-only authoritative name server', False),
        #('expired.caatestsuite-dnssec.com', 'Tests rejection when expired DNSSEC signatures', False), # DNSSEC SHOULD be enabled in production but is not a current requirement for MPIC
        #('missing.caatestsuite-dnssec.com', 'Tests rejection when missing DNSSEC signatures', False), # DNSSEC SHOULD be enabled in production but is not a current requirement for MPIC
        ('blackhole.caatestsuite-dnssec.com', 'Tests rejection when DNSSEC chain goes to non-responsive server', False),
        ('servfail.caatestsuite-dnssec.com', 'Tests rejection when DNSSEC chain goes to server returning SERVFAIL', False),
        ('refused.caatestsuite-dnssec.com', 'Tests rejection when DNSSEC chain goes to server returning REFUSED', False),
        ('xss.caatestsuite.com', 'Tests rejection when issue property has HTML and JS', False),
    ])
    # fmt: on
    @pytest.mark.asyncio
    async def test_api_should_return_is_valid_false_for_all_tests_in_do_not_issue_caa_test_suite(self, domain_or_ip_target, purpose_of_test, is_wildcard_domain):
        async with Client(base_url=API_URL) as client:
            print(f"Running test for {domain_or_ip_target} ({purpose_of_test})")
            if is_wildcard_domain:
                domain_or_ip_target = "*." + domain_or_ip_target
            request = CAAParams(domain_or_ip_target=domain_or_ip_target, 
                check_type=CheckType.CAA,
                caa_check_parameters=CaaCheckParameters(caa_domains=["example.com"]),
            )
            caa_response: Response[CAAResponse] = await post_mpic.asyncio_detailed(client=client, body=request)
            assert caa_response.status_code == 200
            assert caa_response.parsed.is_valid is False




async def main(args):
    print(f"Running basic test. Ryn \"pytest\" to run the full test file.")
    print(args.url)
    client = Client(base_url=args.url)
    async with client as client:
        body = CAAParams(domain_or_ip_target="example.com", check_type=CheckType.CAA, caa_check_parameters=CaaCheckParameters(certificate_type=CaaCheckParametersCertificateType.TLS_SERVER))
        caa_response: Response[CAAResponse] = await post_mpic.asyncio_detailed(client=client, body=body)

        print(caa_response.status_code)
        #print(caa_response.content)
        pp(caa_response.parsed)

if __name__ == '__main__':
    asyncio.run(main(parse_args()))