import argparse
import requests
from pathlib import Path
import os, sys
from pprint import pprint
import ipaddress
import dns.resolver


# https://docs.aws.amazon.com/vpc/latest/userguide/aws-ip-ranges.html
AWS_IP_URL = 'https://ip-ranges.amazonaws.com/ip-ranges.json'
AWS_JSON_FORMAT = {
  "syncToken": "0123456789",
  "createDate": "yyyy-mm-dd-hh-mm-ss",
  "prefixes": [
    {
      "ip_prefix": "cidr",
      "region": "region",
      "network_border_group": "network_border_group",
      "service": "subset"
    }
  ],
  "ipv6_prefixes": [
    {
      "ipv6_prefix": "cidr",
      "region": "region",
      "network_border_group": "network_border_group",
      "service": "subset"
    }
  ]  
}

# Azure
# https://www.microsoft.com/en-us/download/details.aspx?id=56519
# This reaks of microsoft's hard to track download url scheme.
# TODO make dynamic
AZURE_IP_URL = 'https://download.microsoft.com/download/7/1/D/71D86715-5596-4529-9B13-DA13A5DE5B63/ServiceTags_Public_20240819.json'

# GCP 
GCP_IP_URL = 'https://www.gstatic.com/ipranges/cloud.json'


def load_aws(force_refresh:bool=False, never_refresh:bool=False):
    if not force_refresh and not never_refresh:
        pass # todo
    return requests.get(AWS_IP_URL).json()


def load_azure(force_refresh:bool=False, never_refresh:bool=False):
    if not force_refresh and not never_refresh:
        pass # todo
    return requests.get(AZURE_IP_URL).json()


def load_gcp(force_refresh:bool=False, never_refresh:bool=False):
    if not force_refresh and not never_refresh:
        pass # todo
    return requests.get(GCP_IP_URL).json()

def is_gcp(address, gcp):
    _addr = ipaddress.ip_address(address)
    is_4, is_6 = False, False
    if _addr.version == 4:
        is_4 = True
    else:
        is_6 = True
    for prefix in gcp['prefixes']:
        if 'ipv4Prefix' in prefix.keys() and is_4:
            if _addr in ipaddress.ip_network(prefix['ipv4Prefix']):
                return prefix['service']
        if 'ipv6Prefix' in prefix.keys() and is_6:
            if _addr in ipaddress.ip_network(prefix['ipv6Prefix']):
                return prefix['service']
    # Default
    return False


def is_aws(address, aws):
    _addr = ipaddress.ip_address(address)
    if _addr.version == 4:
        for prefix in aws['prefixes']:
            if _addr in ipaddress.ip_network(prefix['ip_prefix']):
                if prefix['service'] == 'AMAZON':
                    continue
                return prefix['service']
    if _addr.version == 6:
        for prefix in aws['ipv6_prefixes']:
            if _addr in ipaddress.ip_network(prefix['ipv6_prefix']):
                if prefix['service'] == 'AMAZON':
                    continue
                return prefix['service']
    # Default
    return(False)


def is_azure(address, azure):
    _addr = ipaddress.ip_address(address)
    for service in azure['values']:
        for prefix in service['properties']['addressPrefixes']:
            if _addr in ipaddress.ip_network(prefix):
                return service['id']
    # Default
    return False


def check_addresses(addresses:list):
    results = {'azure':{}, 'gcp':{}, 'aws':{}, "not_found": 0}
    aws = load_aws()
    gcp = load_gcp()
    azure = load_azure()
    for ip in addresses:
        # Check AWS
        ip = ip.strip()
        service = is_aws(ip, aws)
        if service:
            if service not in results['aws'].keys():
                results['aws'][service] = [ip,]
            else:
                results['aws'][service].append(ip)
            continue

        # Check Azure
        service = is_azure(ip, azure)
        if service:
            if service not in results['azure'].keys():
                results['azure'][service] = [ip,]
            else:
                results['azure'][service].append(ip)
            continue

        # Check GCP
        service = is_gcp(ip, gcp)
        if service:
            if service not in results['gcp'].keys():
                results['gcp'][service] = [ip,]
            else:
                results['gcp'][service].append(ip)
            continue

        results['not_found'] = results['not_found'] + 1
        
    return results
        

# def resolve(hostname):
#     res = dns.resolver.make_resolver_at('1.1.1.1')
#     addresses = []
#     for a in res.resolve(hostname, 'A'):
#         addresses.append(a.address)
#     for a in res.resolve(hostname, 'AAAA'):
#         addresses.append(a.address)
#     for c in res.resolve(hostname, 'cname'):
#         for a in resolve(c):
#             addresses.append(a)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('file', help="File containing IP addresses to check, one per line")

    args = parser.parse_args()
    addresses = []
    with open(args.file, 'r') as f:
        addresses = f.readlines()
    res = check_addresses(addresses)
    pprint(res)



if __name__ == '__main__':
    main()