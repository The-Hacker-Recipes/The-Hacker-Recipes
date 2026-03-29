---
authors: ShutdownRepo, Tednoob17
category: infra
---

# 🛠️ LDAP

## Theory

LDAP (Lightweight Directory Access Protocol) is a standardized network protocol primarily used for directory services — authentication and resource access in networked environments. It operates over TCP, defaulting to port `389` for plain connections and port `636` for LDAPS (LDAP over TLS).

In environments such as Active Directory, LDAP is the primary interface for querying the directory. Anonymous binds are sometimes permitted, which allows unauthenticated enumeration of naming contexts and base attributes. With valid credentials — even low-privileged ones — a significant amount of information becomes accessible.

## Practice

### Enumeration

#### Anonymous bind

When anonymous binds are permitted, naming contexts and base DSE attributes can be retrieved without credentials.

:::tabs
== Unix-like
```bash
# Retrieve naming contexts (base DN)
ldapsearch -x -H ldap://$TARGET -s base namingContexts

# Retrieve all base DSE attributes
ldapsearch -x -H ldap://$TARGET -b "" -s base "(objectclass=*)"
```

== Windows
```powershell
# Using ADSI to retrieve rootDSE properties
[System.DirectoryServices.DirectoryEntry]::new("LDAP://$TARGET/rootDSE").Properties
```

:::

#### Authenticated enumeration

With valid domain credentials, LDAP can be queried for users, groups, computers, GPOs, delegations, and more.

:::tabs
== Unix-like
```bash
# Enumerate all user objects
ldapsearch -x -H ldap://$DC_IP \
  -D "$USER@$DOMAIN" -w "$PASSWORD" \
  -b "dc=$DOMAIN,dc=local" "(objectclass=user)"

# windapsearch — enumerate domain users
python3 windapsearch.py --dc-ip $DC_IP -u "$USER" -p "$PASSWORD" --users

# ldeep — dump all LDAP objects to a local folder
ldeep ldap -u "$USER" -p "$PASSWORD" -d "$DOMAIN" -s ldap://$DC_IP all "dump/$DOMAIN"
```

== Windows
```powershell
# Using PowerView
Get-DomainUser -Server $DC_IP
```

:::

#### Nmap scripts

Port enumeration and service identification can be performed with nmap.

:::tabs
== Unix-like
```bash
nmap -p 389,636 --script=ldap-search,ldap-ls $TARGET
```

:::

## Resources

* [LDAP - Wikipedia](https://en.wikipedia.org/wiki/Lightweight_Directory_Access_Protocol)
* [windapsearch](https://github.com/ropnop/windapsearch)
* [ldeep](https://github.com/franc-pentest/ldeep)
* [LDAP enumeration - GeeksforGeeks](https://www.geeksforgeeks.org/ethical-hacking/ldap-enumeration/)
