---
authors: ShutdownRepo
category: web
---

# Subdomains enumeration

## Theory

When conducting penetration tests on a website, or on a `*.domain.com` scope, finding subdomains of the target can help widen the attack surface. There are many different techniques to find subdomains that can be divided in two main categories.

### Passive techniques

Attackers don't connect directly to the target systems and stay under the radar.

* Certificate Transparency
* ASN Discovery
* Search engines (Google & Bing Dorking)
* DNS aggregators/datasets (Github, Virustotal, DNSdumpster etc)
* Subject alternate name (SAN)
* Using public datasets
* DNS enum using Cloudflare

### Active techniques

Attackers obtain information directly from the target systems. The results may be more useful but can raise some alerts on the defenders side.

* HTTP virtual host fuzzing
* HTTP headers
* DNS zone transfers
* DNS bruteforcing
* DNS zone walking
* DNS cache snooping
* DNS records (CNAME, SPF)
* Reverse DNS sweeping

Detailing every technique mentioned above would be a duplicate to other blogposts that already do (cf. [Resources](domains-enumeration.md#references)).

## Practice

### Google & Bing Dorks

Search engines like Google and Bing offer Dorking features that can be used to gather specific information.

* On Google, the `site:` operator can be used to find subdomains. The minus (`-`) operator can also be used to exclude subdomains that are already known (e.g. `site:*.thehacker.recipes -www`).
* On Bing, the same `site:` operator can be used (e.g. `site:thehacker.recipes`).

### Certificate Transparency

> Certificate Transparency(CT) is a project under which a Certificate Authority(CA) has to publish every SSL/TLS certificate they issue to a public log. An SSL/TLS certificate usually contains domain names, sub-domain names and email addresses.
>
> ([blog.appsecco.com](https://blog.appsecco.com/))

The following websites allow to search through their CT logs: [crt.sh](https://crt.sh/), [censys.io](https://censys.io/), [Facebook's CT monitor](https://developers.facebook.com/tools/ct/), [Google's CT monitor](https://transparencyreport.google.com/https/certificates).

[Findomain](https://github.com/Findomain/Findomain) (Rust), [Subfinder](https://github.com/projectdiscovery/subfinder) (Go) and [Assetfinder](https://github.com/tomnomnom/assetfinder) (Go) mainly rely on Certificate Transparency logs enumeration.

```bash
# Standard enumeration with findomain
findomain -t "target.domain" -a

# Standard enumeration with subfinder
subfinder -d "target.domain"

# Pipe subfinder with httpx to find HTTP services
echo "target.domain" | subfinder -silent | httpx -silent

# Standard enumeration with assetfinder
assetfinder "target.domain"
```

### Virtual host fuzzing

A specific page has been written for this topic.


> [!TIP]
> Read the [Virtual host fuzzing](virtual-host-fuzzing.md) article for more insight


### Amass

OWASP's [Amass](https://github.com/OWASP/Amass) (Go) tool can gather information through DNS bruteforcing, DNS sweeping, NSED zone walking, DNS zone transfer, through web archives, through online DNS datasets and aggregators APIs, etc.

```bash
amass enum --passive -d "domain.com"
```

### DNSRecon

[DNSRecon](https://github.com/darkoperator/dnsrecon) (Python) can enumerate DNS information through the following techniques: check NS records for zone transfers, enumerate records, check for wildcard resolution, TLD expansion, bruteforce subdomain and host A and AAAA records given a wordlist, perform PTR lookup given an IP range, DNS cache snooping, etc.

```bash
# General enumeration
dnsrecon -d "target.domain"

# Standard enumeration and zone transfer (AXFR)
dnsrecon -a -d "target.domain"

# DNS bruteforcing/dictionnary attack
dnsrecon -t brt -d "target.domain" -n "nameserver.com" -D "/path/to/wordlist"
```

### DNS bruteforcing

Apart from [Amass](domains-enumeration.md#amass) and [DNSRecon](domains-enumeration.md#dnsrecord) mentioned above, [gobuster](https://github.com/OJ/gobuster) (go) can be used to do DNS bruteforcing.

```bash
gobuster dns --domain "target.domain" --resolver "nameserver" --wordlist "/path/to/wordlist" 
```

## Resources

[https://blog.appsecco.com/a-penetration-testers-guide-to-sub-domain-enumeration-7d842d5570f6](https://blog.appsecco.com/a-penetration-testers-guide-to-sub-domain-enumeration-7d842d5570f6)

[https://github.com/appsecco/the-art-of-subdomain-enumeration](https://github.com/appsecco/the-art-of-subdomain-enumeration)

[https://lazyhacker.medium.com/subdomain-enumeration-tec-276da39d7e69](https://lazyhacker.medium.com/subdomain-enumeration-tec-276da39d7e69)