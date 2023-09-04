import odoh
import requests

import dns.resolver
import socket

### Service Discovery Method selection
# domain is odoh target.
# ask the resolver for target's conf.

odoh_target = "odoh.dns_resolver.com" 
resolver = "10.0.0.35"

#response = odoh.Fetch_Configs()
response = odoh.SVCB_DNS_Request(odoh_target, resolver, "SVCB")

# send request to Param url=""
# default is cloudflare server.
response = odoh.Fetch_Configs()

# Step 2 parsing the ODoH Config
odoh_configs = odoh.UnmarshalObliviousDoHConfigs(response)
odoh_config = odoh_configs.Configs[0]
# print("ODoH Config",' '.join(str(byte) for byte in response))

# Step 3 Construct DNS Message
# domain is the domain to locate.
domain_name = "www.cloudflare.com"
dns_type = "AAAA"  #28
dns_query = dns.message.make_query(domain_name, dns_type)
query_data = dns_query.to_wire()

# Step 4 Construct Oblivious DNS Message
odohQuery, queryContext = odoh.CreateOdohQuestion(query_data, odoh_config.Contents)

# Step 5 Construct ODNS Message
# default Param odoh_endpoint set to cloudflare.
response = odoh.PrepareHTTPrequest(odohQuery)

# Step 6 Parse the ODNS Response
dns_message = odoh.ValidateEncryptedResponse(response.content, queryContext)

print("\n >> ODoH Resolution\n")
if dns_message:
    print("Header:")
    print("ID:", dns_message.id)

    if hasattr(dns_message, "opcode"):
        print("Opcode:", dns_message.opcode())

    if hasattr(dns_message, "rcode"):
        print("RCODE:", dns_message.rcode())

    if hasattr(dns_message, "rd"):
        print("RD:", dns_message.rd())

    if hasattr(dns_message, "ra"):
        print("RA:", dns_message.ra())

    if hasattr(dns_message, "ad"):
        print("AD:", dns_message.ad())

    if hasattr(dns_message, "cd"):
        print("CD:", dns_message.cd())

    print("\nQuestions:")
    for question in dns_message.question:
        print("Name:", question.name)
        print("Qtype:", question.rdtype)
        print("Qclass:", question.rdclass)

    print("\nAnswers:")
    for answer in dns_message.answer:
        print("Name:", answer.name)
        print("Type:", answer.rdtype)
        print("Class:", answer.rdclass)
        print("TTL:", answer.ttl)
        print("Data:", answer.to_text())

