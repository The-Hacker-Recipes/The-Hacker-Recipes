---
authors: ShutdownRepo, Tednoob17
category: infra
---

# 🛠️ LDAP

## Theory

LDAP (Lightweight Directory Access Protocol) is a standardized network protocol primarily used for directory services — authentication and resource access in networked environments. It operates over TCP, defaulting to port `389` for plain connections and port `636` for LDAPS (LDAP over TLS).

In environments such as Active Directory, LDAP is the primary interface for querying the directory. Anonymous binds are sometimes permitted, which allows unauthenticated enumeration of naming contexts and base attributes. With valid credentials — even low-privileged ones — a significant amount of information becomes accessible, including users, groups, computers, GPOs, and delegation configurations.

### Common LDAP attributes

| Attribute | Description |
|---|---|
| `namingContexts` | Returns the base DN(s) of the directory (e.g. `DC=contoso,DC=local`) |
| `objectClass` | Defines the type of an LDAP object (e.g. `user`, `group`, `computer`) |
| `sAMAccountName` | The logon name of a user or machine account in Active Directory |
| `memberOf` | Lists the groups an object belongs to |
| `userAccountControl` | Bitmask encoding account properties (e.g. disabled, no pre-auth required) |
| `servicePrincipalName` | SPNs associated with an account, relevant for Kerberoasting |
| `adminCount` | Indicates objects under AdminSDHolder protection |

## Practice

### Enumeration

#### Banner grabbing

The LDAP rootDSE (Root Directory Service Entry) is publicly accessible without credentials on most implementations. It exposes useful metadata such as naming contexts, supported LDAP versions, and the domain controller's DNS hostname.

:::tabs
=== Unix-like
```bash
# Retrieve naming contexts (base DN) from rootDSE
ldapsearch -x -H ldap://$TARGET -b "" -s base namingContexts

# Retrieve all rootDSE attributes
ldapsearch -x -H ldap://$TARGET -b "" -s base "(objectclass=*)"
```

=== Windows
```powershell
# Query rootDSE using ADSI
[System.DirectoryServices.DirectoryEntry]::new("LDAP://$TARGET/rootDSE").Properties
```

:::

#### Anonymous bind

When anonymous binds are permitted, directory objects can be enumerated without credentials. The extent of accessible data depends on the server's access control configuration.

:::tabs
=== Unix-like
```bash
# Enumerate all objects accessible via anonymous bind
ldapsearch -x -H ldap://$TARGET -b "$BASE_DN"

# Filter for user objects only
ldapsearch -x -H ldap://$TARGET -b "$BASE_DN" "(objectclass=user)"

# Filter for group objects
ldapsearch -x -H ldap://$TARGET -b "$BASE_DN" "(objectclass=group)"
```

:::

#### Authenticated enumeration

With valid domain credentials, LDAP can be queried for a significantly larger set of objects and attributes, including users, groups, computers, GPOs, and delegation settings.

:::tabs
=== Unix-like
```bash
# Enumerate all user objects
# $BASE_DN: full base DN of the domain, e.g. "DC=contoso,DC=local"
ldapsearch -x -H ldap://$DC_IP \
  -D "$USER@$DOMAIN" -W \
  -b "$BASE_DN" "(objectclass=user)"

# Enumerate computer accounts
ldapsearch -x -H ldap://$DC_IP \
  -D "$USER@$DOMAIN" -W \
  -b "$BASE_DN" "(objectclass=computer)"

# windapsearch (windapsearch.py) — enumerate domain users
python3 windapsearch.py --dc-ip $DC_IP -u "$USER" -p "$PASSWORD" --users

# windapsearch — enumerate domain admins
python3 windapsearch.py --dc-ip $DC_IP -u "$USER" -p "$PASSWORD" --da

# windapsearch — enumerate computers
python3 windapsearch.py --dc-ip $DC_IP -u "$USER" -p "$PASSWORD" --computers

# ldeep — dump all LDAP objects to a local folder
ldeep ldap -u "$USER" -p "$PASSWORD" -d "$DOMAIN" -s ldap://$DC_IP all "dump/$DOMAIN"
```

=== Windows
```powershell
# Using PowerView — enumerate domain users
Get-DomainUser -Server $DC_IP

# Using PowerView — enumerate domain groups
Get-DomainGroup -Server $DC_IP

# Using PowerView — enumerate domain computers
Get-DomainComputer -Server $DC_IP

# Using built-in Active Directory module
Get-ADUser -Filter * -Server $DC_IP
Get-ADComputer -Filter * -Server $DC_IP
```

:::

#### Nmap scripts

Port discovery and LDAP service identification can be performed with nmap.

:::tabs
=== Unix-like
```bash
# Discover LDAP/LDAPS ports and run enumeration scripts
nmap -p 389,636 --script=ldap-search,ldap-rootdse $TARGET

# More aggressive scan with service version detection
nmap -p 389,636 -sV --script=ldap-search,ldap-ls $TARGET
```

:::

### Authentication check

The identity associated with an LDAP bind can be verified using `ldapwhoami`. This is useful to confirm that credentials are valid and to determine the effective bind DN.

:::tabs
=== Unix-like
```bash
# Verify identity of an authenticated bind
ldapwhoami -x -H ldap://$DC_IP -D "$USER@$DOMAIN" -W

# Verify anonymous bind (returns anonymous if allowed)
ldapwhoami -x -H ldap://$TARGET
```

:::

## Resources

* [LDAP - Wikipedia](https://en.wikipedia.org/wiki/Lightweight_Directory_Access_Protocol)
* [windapsearch](https://github.com/ropnop/windapsearch)
* [ldeep](https://github.com/franc-pentest/ldeep)
* [ldapsearch man page](https://linux.die.net/man/1/ldapsearch)
* [HackTricks - LDAP](https://book.hacktricks.xyz/network-services-pentesting/pentesting-ldap)
* [LDAP enumeration - GeeksforGeeks](https://www.geeksforgeeks.org/ethical-hacking/ldap-enumeration/)
