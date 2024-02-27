import sys
import odoh
import argparse

def main():

    # python3 query.py --odohconfig url --target www.google.com --dnstype a

    # python3 query.py --odohconfig dns --ldns 10.0.0.4 --ddr odoh.f5-dns.com --ddrtype svcb --target dns.answer.com --dnstype a

    parser = argparse.ArgumentParser(description='Process some commands.')

    # Common arguments
    parser.add_argument('--odohconfig', type=str.upper, choices=['URL', 'DNS'], help='Method to use', required=True)
    parser.add_argument('--target', help='Target address', required=True)
    parser.add_argument('--dnstype', type=str.upper, help='DNS Type', required=True)
    parser.add_argument('--ddr', help='DDR: odoh.cloudflare-dns.com')
    parser.add_argument('--httpmethod', type=str.upper, default='POST', help='DNS Type')
    parser.add_argument('--odohhost', default=None, help='odohhost address')
    parser.add_argument('--getconfig',  action=argparse.BooleanOptionalAction, help='log odohConfig')
    parser.add_argument('-v', '--verbose',  action=argparse.BooleanOptionalAction, help='verbose')


    # URL specific arguments
    url_group = parser.add_argument_group('URL Specific Arguments')

    # DNS specific arguments
    dns_group = parser.add_argument_group('DNS Specific Arguments')
    url_group.add_argument('--ddrtype', help='DDR RR Type: SVCB RR/ HTTPS RR')
    dns_group.add_argument('--ldns', default='default', help='Local DNS server')

    args = parser.parse_args()

    if args.odohconfig == 'DNS':
        if (args.odohhost):
            print("Error ODOH-DNS method: Unsupported Arguments passed.")
            sys.exit(1)

        dns_response = odoh.dns_odoh(args.ddr, args.odohconfig, args.ddrtype, args.ldns, args.odohhost, args.httpmethod, args.target, args.dnstype, args.v, args.getconfig)

    if args.odohconfig == 'URL':
        if (args.ddr or args.ddrtype):
            print("Error ODOH-URL method: Unsupported Arguments passed.")
            sys.exit(1)

        dns_response = odoh.dns_odoh(args.ddr, args.odohconfig, '', '', args.odohhost, args.httpmethod, args.target, args.dnstype, args.verbose, args.getconfig)

if __name__ == "__main__":
    main()


