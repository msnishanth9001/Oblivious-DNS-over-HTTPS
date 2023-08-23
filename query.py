import requests
import pyhpke
import socket
from pyhpke import CipherSuite, KEMKey, KEMId, KDFId, AEADId
import odoh as config_funs
from dnslib import DNSRecord, QTYPE

import dns.message
import dns.rrset
import dns.renderer
import dns.rdatatype
import dns.name
import dns.resolver


####################
#FETCH  ODoHConfigs
####################

url = 'https://odoh.cloudflare-dns.com/.well-known/odohconfigs'
response = requests.get(url)

if response.status_code == 200:
    print("Request successful!")
    byte_data = response.content
    byte_integers = [byte for byte in byte_data]
    # print("buffer is",' '.join(str(byte) for byte in buffer))
    print(' '.join(str(byte) for byte in byte_integers))

else:
    print(f"Request failed with status code {response.status_code}")

odoh_configs = config_funs.UnmarshalObliviousDoHConfigs(response.content)
odoh_config = odoh_configs.Configs[0]
# temp_check_obj = config_funs.ObliviousDoHConfigs(odoh_config)
# print(temp_check_obj)


######################
#Construct DNS Message
######################

domain_name = "www.google.com."  # Replace with your domain name
dns_type = 28 # QTYPE.AAAA  # (QTYPE.A, QTYPE.HTTPS)
dns_server_address = '1.1.1.1'  # Google Public DNS
dns_server_port = 53
qid = 0
method = "POST"
accept = "application/dns-message"
doh_uri = "/dns-query"
content_type = "application/dns-message"



dnsq = dns.message.make_query(domain_name, dns_type)
dnsq.id = qid

headers = {'accept': accept, ':path': doh_uri}
if method == 'POST' or method == 'PUT':
    body = dnsq.to_wire()
    headers['content-length'] = str(len(body))
    headers['content-type'] = content_type




import requests
import dns.message
import io

# Define the DNS over HTTPS endpoint
doh_endpoint = "https://dns.google/dns-query"  # You can use any other DoH provider

# Define the DNS query parameters
domain_name = "cloudfare-dns.com"  # Replace with the domain name you want to query
dns_type = "A"  # Replace with the DNS record type you want to query (e.g., "A", "MX", etc.)

# Create a DNS query object
dns_query = dns.message.make_query(domain_name, dns_type)

# Encode the DNS query as binary data
query_data = dns_query.to_wire()

# Send the DNS over HTTPS query with the correct Content-Type header
headers = {
    "Content-Type": "application/dns-message",
}
response = requests.post(doh_endpoint, data=query_data, headers=headers)

# Check if the query was successful (HTTP status 200)
if response.status_code == 200:
    # Parse the DNS response from the binary data
    response_data = response.content
    dns_response = dns.message.from_wire(response_data)

    # Extract and print the DNS answers
    answers = dns_response.answer
    if answers:
        print(f"DNS Response for {domain_name}:")
        for answer in answers:
            print(answer)
    else:
        print("No DNS answers found.")
else:
    print(f"Failed to perform DNS query. HTTP status: {response.status_code}")


# h2conn = http2lib.HTTP2Connection(addr_and_port, scheme)
# streamid = h2conn.request(doh_uri, headers, body)


# h2_response = h2conn.getresponse(streamid=streamid, timeout=1)
# h2conn.close_stream(streamid)







print("\n\n\n\n")



KemID = odoh_config.Contents.KemID
KdfID = odoh_config.Contents.KdfID
AeadID = odoh_config.Contents.AeadID
PublicKeyBytes = odoh_config.Contents.PublicKeyBytes

print(KemID, KdfID, AeadID)

suite = CipherSuite.new(KemID, KdfID, AeadID)
pkr = suite.kem.deserialize_public_key(PublicKeyBytes)


key_id = "1"
enc, sender = suite.create_sender_context(pkr)
Q_plain = b"456c6c6f20576f726c64"
aad = '0x01' + str(len(key_id)) + key_id
aad_bytes = bytes(aad, encoding = 'utf-8')
ct = sender.seal(Q_plain, aad_bytes)
separator_bytes = b"|"
Q_encrypted = enc +separator_bytes + ct
print(Q_encrypted)
