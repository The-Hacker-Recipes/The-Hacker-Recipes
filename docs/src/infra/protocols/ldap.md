---
authors: ShutdownRepo, Tednoob17
category: infra
---

# 🛠️ LDAP

## Theory
LDAP (Lightweight Directory Access Protocol) is a standardized network protocol  primarily utilized for user authentication and resource access in a network environment.
The default port used by LDAP on TCP/IP is 389; its secure version, LDAPS, uses TLS (formerly SSL) and typically listens on port 636.

## Basic Usage

- LDAP Search
You can connect to an LDAP server and perform a search using the `ldapsearch` cli command.

```bash
ldapsearch -x -h "$ldap-server" -b "$base-dn" -D "$bind-dn" -w "$password" -s "$search-scope" "$filter"
```
- LDAP Authentication
To authenticate against an LDAP server, you can use the `ldapwhoami` cli command.

```bash
ldapwhoami -x -h "$ldap-server" -D "$bind-dn" -w "$password"
```

###   Authentication Reconnaissance & Enumeration
####  Initial Discovery
```bash
nmap -p 389,636 --script=ldap-search,ldap-ls "$target_ip_range_or_domain_controller"
# -sV: Service version detection can reveal the underlying directory service
# --script=ldap-search: This script allows you to perform generic LDAP searches.
# --script=ldap-ls: Lists directory contents.
```

#### Banner Grabbing
Even without authenticating, an LDAP server might reveal valuable meta-information.

:::tabs
=== ldapsearch
```bash
ldapsearch -x -h "$target_ip" -p 389 -s base namingContexts
# -x: Use simple authentication (often for anonymous bind if allowed).
# -h: Host IP.
# -p: Port.
# -s base: Search base object only.
# namingContexts: Attribute to retrieve the base DN (Distinguished Name) of the domain, e.g., dc=example,dc=com.
ldapsearch -x -h "$ldap-server" -b "" -s base "(objectclass=*)"
# Retrieve rootDSE/base attributes (e.g., namingContexts), not all directory objects

```

=== Netcat/Telnet

```bash
nc -nv $target_ip 389
# LDAP uses BER/ASN.1 and won't return meaningful text banners over raw TCP.
# Use ldapsearch against rootDSE to safely enumerate server info:
# ldapsearch -x -H ldap://"$target_ip" -b "" -s base "(objectclass=*)" 
```
:::

####  Authenticated & Unauthenticated Enumeration

A low-privileged set of credentials, such as a phishing attack or an exposed web service, can unlock a vast amount of information.
:::tabs
=== enum4linux
 `enum4linux` : While often associated with SMB, `enum4linux` can perform some basic **LDAP** enumeration, especially useful for Active Directory.

```bash
enum4linux -a "$target_ip"
```
=== windapsearch
`windapsearch` : A powerful Python tool for comprehensive LDAP queries in Windows domains, especially when you have valid credentials.

```bash
python3 windapsearch.py --dc-ip "$target_dc_ip" -u "$domain_user" -p "$password" --users
# Basic usage to enumerate users
```
=== ldeep
`ldeep` : Another useful Python tool for dumping information like delegations, GPOs, trusts, users, and machines from LDAP.
```bash
ldeep ldap -u "$USER" -p "$PASSWORD" -d "$DOMAIN" -s ldap://"$DC_IP" all "dump/$DOMAIN"
```

=== ldapsearch

```bash
ldapsearch -x -h <ldap-server> -b "ou=users,dc=example,dc=com" "(objectclass=inetOrgPerson)"
```
:::

## Attacks Vector
> [!WARNING]
> The following section is for educational and defensive purposes only.
> Unauthorized access or modification of systems is illegal.

- **Backdoor Account Creation**: Attackers with write permissions might create hidden admin accounts.
- **Mitigation**: Enforce least privilege, monitor for new account creation, and regularly audit privileged groups.


```bash
ldapmodify -x -H ldap://"$dc_ip" -D "CN=adminuser,CN=Users,DC=example,DC=com" -w "adminpassword" -f add_admin.ldif
# add: member
# Create an ldif file (e.g., add_admin.ldif)
# member: CN=your_vulnerable_user_account,CN=Users,DC=example,DC=com
```


## Resources
* [LDAP Wikipedia](https://en.wikipedia.org/wiki/Lightweight_Directory_Access_Protocol)
* [gokulg.med](https://medium.com/@gokulg.me/introduction-92199491c808)
* [vaadata](https://www.vaadata.com/blog/active-directory-security-best-practices-vulnerabilities-and-attacks/)
* [purplesec](https://purplesec.us/learn/privilege-escalation-attacks/)
* [geeksforgeeks](https://www.geeksforgeeks.org/ethical-hacking/ldap-enumeration/)
