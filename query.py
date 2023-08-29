import requests
import pyhpke
import socket
from pyhpke import CipherSuite, KEMKey, KEMId, KDFId, AEADId
import odoh
from dnslib import DNSRecord, QTYPE

import dns.message
import dns.rrset
import dns.renderer
import dns.rdatatype
import dns.name
import dns.resolver

import io

####################
#FETCH  ODoHConfigs
####################

url = 'https://odoh.cloudflare-dns.com/.well-known/odohconfigs'
response = requests.get(url)

if response.status_code == 200:
    print("Request successful!")
    byte_data = response.content
    byte_integers = [byte for byte in byte_data]
    print(">>>>> == response is",' '.join(str(byte) for byte in byte_integers))

else:
    print(f"Request failed with status code {response.status_code}")

odoh_configs = odoh.UnmarshalObliviousDoHConfigs(response.content)
odoh_config = odoh_configs.Configs[0]

# temp_check_obj = config_funcs.ObliviousDoHConfigs(odoh_config)
# print(temp_check_obj)

######################
#Construct DNS Message
######################

domain_name = "www.cloudflare.com"
dns_type = "AAAA"  #28
dns_query = dns.message.make_query(domain_name, dns_type)

query_data = dns_query.to_wire()

# dns_query_Packed = [byte for byte in query_data]
# print(">>>>> == dns_query_Packed is",' '.join(str(byte) for byte in dns_query_Packed))

odohQuery, queryContext = odoh.create_odoh_question(query_data, odoh_config.Contents)

print(" === === === ")

req = odoh.prepareHttpRequest(odohQuery)

print("\n hehe")
