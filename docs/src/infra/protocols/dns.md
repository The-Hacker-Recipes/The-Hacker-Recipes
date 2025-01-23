---
authors: ShutdownRepo, Tednoob17
---

# 🛠️ DNS

## Theory
DNS lets users connect to websites using domain names instead of IP addresses. The Domain Name System (DNS) is the phonebook of the Internet.
Humans access information online through domain names, like thehacker.recipes. Web browsers interact through Internet Protocol (IP) addresses.
DNS translates domain names to IP addresses so browsers can load Internet resources.

The default port of DNS is 53.

## Enumeration
### Automation

:::tabs

=== dig
The dig command is a powerful network tool for querying (DNS) servers.
It helps diagnose and resolve DNS-related problems, essential for maintaining network stability and performance.

```bash
# Dns Query
dig thehacker.recipes

# Querying a dns record type (A record for ip address)
dig  thehacker.recipes A

# Querying a name server record list
dig  thehacker.recipes NS

# Tracing the DNS path
dig thehacker.recipes  +trace
```
=== nslookup
Displays information that you can use to diagnose (DNS) infrastructure.

```bash
# Operate a DNS Query
nslookup thehacker.recipes

# Query a mail DNS record (MX record)
nslookup -type=MX thehacker.recipes

# Query a specific DNS server
nslookup thehacker.recipes $DNS_IP
```

=== host

host is a simple utility for performing Domain Name System lookups.

```bash
# Simple DNS Query
host thehacker.recipes

# Query a mail DNS record (MX record)
host -t MX thehacker.recipes

# Perform a reverse DNS lookup
host $IP_ADDRESS
```

=== whois

```bash
# Simple DNS Query
whois thehacker.recipes
```
:::

### Any Record Query

```bash
dig any thehacker.recipes @$IP_ADDR
```

### Zone Transfer
DNS zone transfers using the AXFR protocol are the simplest mechanism to replicate DNS records across DNS servers.

```bash
# With ip address
dig axfr @$DNS_IP

# With guessing the domain
dig axfr @$DNS_IP $DOMAIN

# Alternatively, you can use fierce for zone transfers or dictionary attacks
# DNS reconnaissance and subdomain enumeration tool with recursive search and wildcard detection.
fierce --domain $DOMAIN --dns-servers $DNS_IP
```



## Resources
https://academy.hackthebox.com/module/144/section/1251
