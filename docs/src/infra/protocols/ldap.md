---
authors: ShutdownRepo, felixbillieres
category: infra
---

# LDAP

## Theory

LDAP (Lightweight Directory Access Protocol) is a vendor-neutral protocol designed for accessing and managing directory information services. It typically runs on port `389/TCP` (LDAP) or `636/TCP` (LDAPS - LDAP over SSL/TLS). In Active Directory environments, LDAP also uses port `3268/TCP` (Global Catalog) and `3269/TCP` (Global Catalog over TLS), which are commonly used for cross-domain forest enumeration.

LDAP uses a hierarchical structure where each entry has a Distinguished Name (DN) and attributes (key-value pairs) depending on the entry type (user, group, computer, etc.). In Active Directory, common DN structures include:
* `CN=Users,DC=domain,DC=tld`
* `CN=Computers,DC=domain,DC=tld`
* `OU=OUname,DC=domain,DC=tld`

> [!NOTE]
> Kerberos is not LDAP - they are different protocols. However, in pentesting, LDAP enumeration and Kerberos abuse are often related, as LDAP is used to query Active Directory information that can then be exploited via Kerberos attacks.

Exploiting LDAP can lead to:
* User and group enumeration
* Password policy disclosure
* Sensitive information extraction
* Lateral movement within the network
* Privilege escalation

## Enumeration

### Port scanning

LDAP typically runs on port `389/TCP` (LDAP) or `636/TCP` (LDAPS). In Active Directory environments, also scan for Global Catalog ports `3268/TCP` and `3269/TCP` (GC over TLS).

```bash
# Basic port scan
nmap -p 389,636,3268,3269 $TARGET

# Service version detection
nmap -p 389,636,3268,3269 -sV $TARGET

# LDAP-specific scripts
nmap -p 389 --script ldap-rootdse,ldap-search $TARGET
```

### Anonymous binding

LDAP anonymous binding allows unauthenticated access to directory information. **In Active Directory, anonymous bind is disabled by default since Server 2003**, but should always be tested. Some attributes remain readable anonymously (RootDSE, namingContexts).

```bash
# Test anonymous binding
ldapsearch -x -h $TARGET -s base

# Test with ldapsearch
ldapsearch -x -H ldap://$TARGET -s base namingcontexts

# Test with NetExec
netexec ldap $TARGET --no-bruteforce
```

> [!TIP]
> Even with anonymous binding disabled, some metadata (naming contexts, DNS server name, Domain Functional Level) can often be obtained anonymously. Easy enumeration via anonymous bind is more common with OpenLDAP or old AD versions than modern Active Directory environments.

### Banner grabbing

```bash
# Using ldapsearch (recommended method)
ldapsearch -x -H ldap://$TARGET -s base -b "" "(objectClass=*)" +
```

> [!NOTE]
> Using `nc -vn $TARGET 389` does not work effectively for LDAP banner grabbing. LDAP does not return a simple plaintext banner, and `nc` generally returns nothing except an unusable handshake. Use `ldapsearch` to properly obtain LDAP server information.

### Basic information

Gather basic server information and metadata.

```bash
# Get root DSE (Directory Service Entry) - basic server information
ldapsearch -x -H ldap://$TARGET -s base -b "" "(objectClass=*)" +

# Get naming contexts
ldapsearch -x -H ldap://$TARGET -s base namingcontexts

# Get supported LDAP version
ldapsearch -x -H ldap://$TARGET -s base supportedLDAPVersion

# Get supported SASL mechanisms
ldapsearch -x -H ldap://$TARGET -s base supportedSASLMechanisms
```

### Authenticated queries

Once authenticated, you can query the directory for detailed information.

::: tabs

=== ldapsearch

```bash
# Authenticate and query
ldapsearch -x \
    -H ldap://$TARGET \
    -D "CN=user,CN=Users,DC=domain,DC=local" \
    -w password \
    -b "DC=domain,DC=local"

# Query with domain credentials (domain\\user format)
ldapsearch -x \
    -H ldap://$TARGET \
    -D "domain\\user" \
    -w password \
    -b "DC=domain,DC=local"

# Query with domain credentials (user@domain.local format - commonly used for AD)
ldapsearch -x \
    -H ldap://domain.local \
    -D "user@domain.local" \
    -W \
    -b "DC=domain,DC=local"
```

=== NetExec

[NetExec](https://github.com/Pennyw0rth/NetExec) can execute custom LDAP queries.

```bash
# Execute LDAP query (default attributes)
netexec ldap $TARGET -u username -p password --query "(sAMAccountName=Administrator)"

# Execute LDAP query with specific attributes
netexec ldap $TARGET -u username -p password --query "(sAMAccountName=Administrator)" "sAMAccountName objectClass pwdLastSet"

# Basic LDAP enumeration
netexec ldap $TARGET -d domain -u user -p password

# Bruteforce LDAP credentials
netexec ldap $TARGET -d domain -u users.txt -p passwords.txt
```

:::

## User enumeration

::: tabs

=== ldapsearch

```bash
# List all users
ldapsearch -x \
    -H ldap://$TARGET \
    -D "domain\\user" \
    -w password \
    -b "DC=domain,DC=local" \
    "(objectClass=user)" \
    sAMAccountName

# List users with description (often contain passwords or sensitive info)
ldapsearch -x \
    -H ldap://$TARGET \
    -D "domain\\user" \
    -w password \
    -b "DC=domain,DC=local" \
    "(objectClass=user)" \
    sAMAccountName description

# List disabled users (userAccountControl flag: 2)
# Uses LDAP_MATCHING_RULE_BIT_AND (OID: 1.2.840.113556.1.4.803)
ldapsearch -x \
    -H ldap://$TARGET \
    -D "domain\\user" \
    -w password \
    -b "DC=domain,DC=local" \
    "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2))" \
    sAMAccountName

# List users with password never expires (userAccountControl flag: 65536)
ldapsearch -x \
    -H ldap://$TARGET \
    -D "domain\\user" \
    -w password \
    -b "DC=domain,DC=local" \
    "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=65536))" \
    sAMAccountName

# List users that don't require Kerberos pre-authentication (ASREPRoastable) (userAccountControl flag: 4194304)
ldapsearch -x \
    -H ldap://$TARGET \
    -D "domain\\user" \
    -w password \
    -b "DC=domain,DC=local" \
    "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))" \
    sAMAccountName
```

=== NetExec

[NetExec](https://github.com/Pennyw0rth/NetExec) can enumerate users.

```bash
# Enumerate all users
netexec ldap $TARGET -u username -p password --users

# Get users with descriptions (often contain passwords or sensitive info)
netexec ldap $TARGET -u username -p password -M get-desc-users
```

:::

## Group enumeration

::: tabs

=== ldapsearch

```bash
# List all groups
ldapsearch -x \
    -H ldap://$TARGET \
    -D "domain\\user" \
    -w password \
    -b "DC=domain,DC=local" \
    "(objectClass=group)" \
    sAMAccountName

# List domain admins
# Note: In environments with localized languages, the CN may differ (e.g., "Administrateurs du domaine" in French)
# This query may fail in non-English environments
ldapsearch -x \
    -H ldap://$TARGET \
    -D "domain\\user" \
    -w password \
    -b "DC=domain,DC=local" \
    "(&(objectClass=group)(cn=Domain Admins))" \
    member

# List group members
ldapsearch -x \
    -H ldap://$TARGET \
    -D "domain\\user" \
    -w password \
    -b "DC=domain,DC=local" \
    "(&(objectClass=group)(cn=GroupName))" \
    member
```

=== NetExec

[NetExec](https://github.com/Pennyw0rth/NetExec) can enumerate groups.

```bash
# Enumerate all groups
netexec ldap $TARGET -u username -p password --groups
```

:::

## Computer enumeration

::: tabs

=== ldapsearch

```bash
# List all computers
ldapsearch -x \
    -H ldap://$TARGET \
    -D "domain\\user" \
    -w password \
    -b "DC=domain,DC=local" \
    "(objectClass=computer)" \
    sAMAccountName

# List domain controllers
ldapsearch -x \
    -H ldap://$TARGET \
    -D "domain\\user" \
    -w password \
    -b "DC=domain,DC=local" \
    "(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))" \
    sAMAccountName dNSHostName
```

=== NetExec

[NetExec](https://github.com/Pennyw0rth/NetExec) can enumerate computers.

```bash
# Enumerate all computers
netexec ldap $TARGET -u username -p password --computers
```

:::

## Password policy

```bash
# Get password policy
ldapsearch -x \
    -H ldap://$TARGET \
    -D "domain\\user" \
    -w password \
    -b "DC=domain,DC=local" \
    "(objectClass=domainDNS)" \
    minPwdLength maxPwdAge pwdHistoryLength \
    lockoutThreshold lockoutDuration
```

## Trust relationships

```bash
# List trust relationships with important attributes
ldapsearch -x -H ldap://$TARGET \
  -D "domain\\user" -w password \
  -b "DC=domain,DC=local" \
  "(objectClass=trustedDomain)" \
  trustPartner trustDirection trustAttributes trustType flatName
```

> [!NOTE]
> Important attributes for trust relationships include:
> * `flatName` — NetBIOS name of the trusted domain
> * `trustPartner` — FQDN of the trusted domain
> * `trustDirection` — trust direction (inbound, outbound, bidirectional)
> * `trustType` — trust type (Windows, forest, MIT Kerberos, etc.)
> * `trustAttributes` — flags describing transitivity, selective auth, etc.

## Resources

[https://book.hacktricks.xyz/network-services-pentesting/pentesting-ldap](https://book.hacktricks.xyz/network-services-pentesting/pentesting-ldap)

[https://www.netexec.wiki/](https://www.netexec.wiki/)

[https://ldapwiki.com/wiki/LDAP%20Search%20Best%20Practices](https://ldapwiki.com/wiki/LDAP%20Search%20Best%20Practices)
