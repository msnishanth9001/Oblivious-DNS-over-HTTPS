import sys
import odoh

def main():
    if sys.argv[1].upper() == 'DNS':
        if len(sys.argv) != 8:
            print("Usage: python query.py arg1 arg2 arg3 arg4 arg5 arg6 arg7")
            return
        else:
            configFetch_method = sys.argv[1]
            resolver = sys.argv[2]
            ddr = sys.argv[3]
            ddrType = sys.argv[4]
            http_method = sys.argv[5]
            lookup_domain = sys.argv[6]
            lookup_domain_rr_type = sys.argv[7]

            dns_response = odoh.dns_odoh(ddr, configFetch_method, ddrType, resolver, http_method, lookup_domain, lookup_domain_rr_type)

    elif sys.argv[1].upper() == 'URL':
        if len(sys.argv) != 6:
            print("Usage: python query.py arg1 arg2 arg3 arg4 arg5")
            return
        else:
            configFetch_method = sys.argv[1]
            ddr = sys.argv[2]
            http_method = sys.argv[3]
            lookup_domain = sys.argv[4]
            lookup_domain_rr_type = sys.argv[5]

            dns_response = odoh.dns_odoh(ddr, configFetch_method, '', '', http_method, lookup_domain, lookup_domain_rr_type)

    """
    python3 rquery.py 10.0.0.4 odoh.f5-dns.com svcb POST dns.answer.com a

    resolver = "1.1.1.1"
    ddr/ odoh_target = "odoh.cloudflare-dns.com"
    ddrType = SVCB/ HTTPS
    http_method = POST/ GET

    lookup_domain = "www.github.com"
    lookup_domain_rr_type = A

    resolver = sys.argv[1]
    configFetch_method = sys.argv[2]
    ddr = sys.argv[3]
    ddrType = sys.argv[4]
    http_method = sys.argv[5]
    lookup_domain = sys.argv[6]
    lookup_domain_rr_type = sys.argv[7]

    print("Resolver:", resolver)
    print("configFetch_method", configFetch_method)
    print("ODOH Target/ URL:", ddr)
    print("ddrType:", ddrType)
    print("HTTP Method:", http_method)
    print("Query Domain:", lookup_domain)
    print("Query_RR Type:", lookup_domain_rr_type)

    dns_response = odoh.dns_odoh(ddr, ddrType, resolver, http_method, lookup_domain, lookup_domain_rr_type)
    """

    print("DNS Answer via ODOH: ", dns_response)

if __name__ == "__main__":
    main()




