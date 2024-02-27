# ObliviousDNS-over-HTTPS

ODoH allows hiding client IP addresses via proxying encrypted DNS transactions. This improves privacy of DNS operations by not allowing any one server entity to be aware of both the client IP address and the content of DNS Query and Answer.

It currently supports the following functionalities:

- [ ] DoH Query:
- [x] ODoH Query:
- [ ] ODoH Query via Proxy:

## Usage

### ODoH query to target VIA DNS for odohConfig

```sh
python3 query.py --odohconfig dns --ldns 10.0.0.4 --ddr odoh.f5-dns.com --ddrtype svcb --target dns.answer.com --dnstype a -v
```

### ODoH query to target VIA URL for odohConfig

```sh
python3 query.py --odohconfig url --target odoh.cloudflare-dns.com --dnstype aaaa
```

### Fetch ODoH configuration

```sh
python3 query.py --odohconfig dns --ldns 10.0.0.4 --ddr odoh.f5-dns.com --ddrtype svcb --target dns.answer.com --dnstype aaaa --getconfig -v
```