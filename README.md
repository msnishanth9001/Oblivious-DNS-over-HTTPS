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

### Note

> This tool includes a sub command for benchmarking various protocols and has been
> used for performing measurements presented in this [arxiv paper](https://arxiv.org/abs/2011.10121). There are also
> traces of telemetry which are used for the same purpose in an effort to reproduce the results of the paper.
