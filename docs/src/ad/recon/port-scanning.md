---
authors: ShutdownRepo
category: ad
---

# Port scanning

In an Active Directory domain, domain controllers can be easily spotted depending on what services they host. Each service is usually accessible specific TCP and/or UDP port(s) making the DCs stand out in the network. Here is a list of ports to look for when hunting for domain controllers.

* `53/TCP` and `53/UDP` for DNS
* `88/TCP` for Kerberos authentication
* `135/TCP` and `135/UDP` MS-RPC epmapper (EndPoint Mapper)
* `137/TCP` and `137/UDP` for NBT-NS
* `138/UDP` for NetBIOS datagram service
* `139/TCP` for NetBIOS session service
* `389/TCP` for LDAP
* `636/TCP` for LDAPS (LDAP over TLS/SSL)
* `445/TCP` and `445/UDP` for SMB
* `464/TCP` and `445/UDP` for Kerberos password change
* `3268/TCP` for LDAP Global Catalog
* `3269/TCP` for LDAP Global Catalog over TLS/SSL

The [nmap](https://nmap.org/) utility can be used to scan for open ports in an IP range.

```bash
# -sS for TCP SYN scan
# -n for no name resolution
# --open to only show (possibly) open port(s)
# -p for port(s) number(s) to scan
nmap -sS -n --open -p 88,389 $IP_RANGE
```