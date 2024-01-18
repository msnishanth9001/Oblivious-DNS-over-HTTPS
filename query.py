import sys
import odoh

def main():
    if len(sys.argv) != 7:
        print("Usage: python query.py arg1 arg2 arg3 arg4 arg5 arg6")
        return

    """
    resolver = "1.1.1.1"
    ddr/ odoh_target = "odoh.cloudflare-dns.com"
    ddrType = SVCB/ HTTPS
    http_method = POST/ GET

    lookup_domain = "www.github.com"
    lookup_domain_rr_type = A
    """

    resolver = sys.argv[1]
    ddr = sys.argv[2]
    ddrType = sys.argv[3]
    http_method = sys.argv[4]
    lookup_domain = sys.argv[5]
    lookup_domain_rr_type = sys.argv[6]

    print("Resolver:", resolver)
    print("ODOH Target:", ddr)
    print("HTTP Method:", http_method)
    print("Query Domain:", lookup_domain)
    print("Query_RR Type:", lookup_domain_rr_type)

    dns_response = odoh.dns_odoh(ddr, ddrType, resolver, http_method, lookup_domain, lookup_domain_rr_type)

    print("DNS Answer via ODOH: ", dns_response)

if __name__ == "__main__":
    main()



