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

## Practice

### Enumeration

#### Port scanning

LDAP typically runs on port `389/TCP` (LDAP) or `636/TCP` (LDAPS). In Active Directory environments, also scan for Global Catalog ports `3268/TCP` and `3269/TCP` (GC over TLS).

::: tabs

=== Unix-like

```bash
# Basic port scan
nmap -p 389,636,3268,3269 $TARGET

# Service version detection
nmap -p 389,636,3268,3269 -sV $TARGET

# LDAP-specific scripts
nmap -p 389 --script ldap-rootdse,ldap-search $TARGET
```

=== Windows

```powershell
# Basic port scan using Test-NetConnection
Test-NetConnection -ComputerName $TARGET -Port 389
Test-NetConnection -ComputerName $TARGET -Port 636
Test-NetConnection -ComputerName $TARGET -Port 3268
Test-NetConnection -ComputerName $TARGET -Port 3269

# Using nmap (if available)
nmap -p 389,636,3268,3269 $TARGET
```

:::

#### Anonymous binding

LDAP anonymous binding allows unauthenticated access to directory information. Anonymous bind is often restricted in Active Directory environments (commonly hardened since the Windows Server 2003 era), but it should still be tested. Some attributes remain readable anonymously (RootDSE, namingContexts).

::: tabs

=== Unix-like

```bash
# Test anonymous binding
ldapsearch -x -h $TARGET -s base

# Test with ldapsearch
ldapsearch -x -H ldap://$TARGET -s base namingcontexts

# Using NetExec (if available)
netexec ldap $TARGET --no-bruteforce
```

=== Windows

```powershell
# Using LDP.exe (GUI tool)
# Launch LDP.exe, connect to $TARGET:389, then bind anonymously

# Using PowerShell with System.DirectoryServices.Protocols (LDAP)
$ldap = New-Object System.DirectoryServices.Protocols.LdapConnection("$TARGET")
$ldap.AuthType = [System.DirectoryServices.Protocols.AuthType]::Anonymous
$ldap.Bind()

# Using PowerShell with System.DirectoryServices.Protocols (LDAPS)
$identifier = New-Object System.DirectoryServices.Protocols.LdapDirectoryIdentifier("$TARGET", 636)
$ldap = New-Object System.DirectoryServices.Protocols.LdapConnection($identifier)
$ldap.SessionOptions.SecureSocketLayer = $true
$ldap.AuthType = [System.DirectoryServices.Protocols.AuthType]::Anonymous
$ldap.Bind()

# Using PowerShell with System.DirectoryServices.Protocols (Global Catalog over TLS)
$identifier = New-Object System.DirectoryServices.Protocols.LdapDirectoryIdentifier("$TARGET", 3269)
$ldap = New-Object System.DirectoryServices.Protocols.LdapConnection($identifier)
$ldap.SessionOptions.SecureSocketLayer = $true
$ldap.AuthType = [System.DirectoryServices.Protocols.AuthType]::Anonymous
$ldap.Bind()
```

:::

> [!TIP]
> Even with anonymous binding disabled, some metadata (naming contexts, DNS server name, Domain Functional Level) can often be obtained anonymously. Easy enumeration via anonymous bind is more common with OpenLDAP or old AD versions than modern Active Directory environments.

#### RootDSE query

The RootDSE (Directory Service Entry) provides basic server information and metadata. Querying RootDSE is useful for service identification and enumeration.

::: tabs

=== Unix-like

```bash
# Using ldapsearch (recommended method)
ldapsearch -x -H ldap://$TARGET -s base -b "" "(objectClass=*)" +
```

=== Windows

```powershell
# Using LDP.exe
# Launch LDP.exe, connect to $TARGET:389, view RootDSE

# Using PowerShell
$ldap = New-Object System.DirectoryServices.Protocols.LdapConnection("$TARGET")
$request = New-Object System.DirectoryServices.Protocols.SearchRequest
$request.DistinguishedName = ""
$request.Scope = [System.DirectoryServices.Protocols.SearchScope]::Base
$request.Filter = "(objectClass=*)"
$ldap.SendRequest($request)
```

:::

> [!NOTE]
> Using `nc -vn $TARGET 389` does not work effectively for LDAP banner grabbing. LDAP does not return a simple plaintext banner, and `nc` generally returns nothing except an unusable handshake. Use `ldapsearch` or LDAP tools to properly obtain LDAP server information.

#### Basic information

Gather basic server information and metadata.

::: tabs

=== Unix-like

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

=== Windows

```powershell
# Using PowerShell with System.DirectoryServices.Protocols
$ldap = New-Object System.DirectoryServices.Protocols.LdapConnection("$TARGET")
$ldap.Credential = New-Object System.Net.NetworkCredential($null, $null)
$request = New-Object System.DirectoryServices.Protocols.SearchRequest
$request.DistinguishedName = ""
$request.Scope = [System.DirectoryServices.Protocols.SearchScope]::Base
$request.Filter = "(objectClass=*)"
$request.Attributes.Add("namingContexts") | Out-Null
$request.Attributes.Add("supportedLDAPVersion") | Out-Null
$request.Attributes.Add("supportedSASLMechanisms") | Out-Null
$ldap.SendRequest($request)

# Using ADSI (if RSAT is installed)
$rootDSE = [ADSI]"LDAP://$TARGET/RootDSE"
$rootDSE.Properties["namingContexts"]
$rootDSE.Properties["supportedLDAPVersion"]
```

:::

### Authentication

LDAP supports several authentication methods:

* **Anonymous binding**: Unauthenticated access (see [Anonymous binding](#anonymous-binding) section)
* **Simple authentication**: Username/password authentication
* **SASL authentication**: Simple Authentication and Security Layer mechanisms (GSSAPI/Kerberos, DIGEST-MD5, etc.)

In Active Directory environments, LDAP authentication typically uses:
* Distinguished Name (DN) format: `CN=$USER,CN=Users,DC=$DOMAIN,DC=local`
* Domain credentials format: `$DOMAIN\$USER` or `$USER@$DOMAIN.local`

#### Bruteforce

::: tabs

=== Unix-like

```bash
# Using NetExec
netexec ldap $TARGET -d $DOMAIN -u users.txt -p passwords.txt

# Using Hydra
hydra -l $USER -P /path/to/passwords.txt ldap://$TARGET
```

=== Windows

```powershell
# Using NetExec (if available)
netexec ldap $TARGET -d $DOMAIN -u users.txt -p passwords.txt

# Using PowerShell for basic credential testing
$users = Get-Content users.txt
$passwords = Get-Content passwords.txt
foreach ($user in $users) {
    foreach ($pass in $passwords) {
        try {
            $ldap = New-Object System.DirectoryServices.Protocols.LdapConnection("$TARGET")
            $ldap.Credential = New-Object System.Net.NetworkCredential($user, $pass, $DOMAIN)
            $ldap.Bind()
            Write-Host "Valid: $user:$pass"
        } catch {
            # Invalid credentials
        }
    }
}
```

:::

#### Authenticated queries

Once authenticated, directory queries can be executed to retrieve detailed information.

::: tabs

=== Unix-like

```bash
# Authenticate and query
ldapsearch -x \
    -H ldap://$TARGET \
    -D "CN=$USER,CN=Users,DC=$DOMAIN,DC=local" \
    -w $PASSWORD \
    -b "DC=$DOMAIN,DC=local"

# Query with domain credentials (domain\\user format - AD-specific)
# Note: This format is AD-specific and may not work with non-AD LDAP servers
ldapsearch -x \
    -H ldap://$TARGET \
    -D "$DOMAIN\\$USER" \
    -w $PASSWORD \
    -b "DC=$DOMAIN,DC=local"

# Query with domain credentials (user@domain.local format - commonly used for AD)
ldapsearch -x \
    -H ldap://$DOMAIN.local \
    -D "$USER@$DOMAIN.local" \
    -W \
    -b "DC=$DOMAIN,DC=local"

# Using NetExec for custom queries
netexec ldap $TARGET -u $USER -p $PASSWORD --query "(sAMAccountName=Administrator)"
netexec ldap $TARGET -u $USER -p $PASSWORD --query "(sAMAccountName=Administrator)" "sAMAccountName objectClass pwdLastSet"
netexec ldap $TARGET -d $DOMAIN -u $USER -p $PASSWORD
```

=== Windows

```powershell
# Using PowerShell with System.DirectoryServices.Protocols
$ldap = New-Object System.DirectoryServices.Protocols.LdapConnection("$TARGET")
$ldap.Credential = New-Object System.Net.NetworkCredential($USER, $PASSWORD, $DOMAIN)
$request = New-Object System.DirectoryServices.Protocols.SearchRequest
$request.DistinguishedName = "DC=$DOMAIN,DC=local"
$request.Scope = [System.DirectoryServices.Protocols.SearchScope]::Subtree
$request.Filter = "(objectClass=*)"
$ldap.SendRequest($request)

# Using ADSI (if RSAT is installed)
$searcher = New-Object System.DirectoryServices.DirectorySearcher
$searcher.SearchRoot = [ADSI]"LDAP://$TARGET/DC=$DOMAIN,DC=local"
$searcher.Filter = "(objectClass=*)"
$searcher.FindAll()

# Using NetExec (if available)
netexec ldap $TARGET -u $USER -p $PASSWORD --query "(sAMAccountName=Administrator)"
```

:::

### User enumeration

::: tabs

=== Unix-like

```bash
# List all users
ldapsearch -x \
    -H ldap://$TARGET \
    -D "$DOMAIN\\$USER" \
    -w $PASSWORD \
    -b "DC=$DOMAIN,DC=local" \
    "(objectClass=user)" \
    sAMAccountName

# List users with description (often contain passwords or sensitive info)
ldapsearch -x \
    -H ldap://$TARGET \
    -D "$DOMAIN\\$USER" \
    -w $PASSWORD \
    -b "DC=$DOMAIN,DC=local" \
    "(objectClass=user)" \
    sAMAccountName description

# List disabled users (userAccountControl flag: 2)
# Uses LDAP_MATCHING_RULE_BIT_AND (OID: 1.2.840.113556.1.4.803)
ldapsearch -x \
    -H ldap://$TARGET \
    -D "$DOMAIN\\$USER" \
    -w $PASSWORD \
    -b "DC=$DOMAIN,DC=local" \
    "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2))" \
    sAMAccountName

# List users with password never expires (userAccountControl flag: 65536)
ldapsearch -x \
    -H ldap://$TARGET \
    -D "$DOMAIN\\$USER" \
    -w $PASSWORD \
    -b "DC=$DOMAIN,DC=local" \
    "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=65536))" \
    sAMAccountName

# List users that don't require Kerberos pre-authentication (ASREPRoastable)
# These users are vulnerable to AS-REP roasting attacks (userAccountControl flag: 4194304)
ldapsearch -x \
    -H ldap://$TARGET \
    -D "$DOMAIN\\$USER" \
    -w $PASSWORD \
    -b "DC=$DOMAIN,DC=local" \
    "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))" \
    sAMAccountName

# Using NetExec
netexec ldap $TARGET -u $USER -p $PASSWORD --users
netexec ldap $TARGET -u $USER -p $PASSWORD -M get-desc-users
```

=== Windows

```powershell
# Using PowerShell with Get-ADUser (requires RSAT)
Get-ADUser -Filter * -Server $TARGET -Properties sAMAccountName, Description

# List disabled users
Get-ADUser -Filter {Enabled -eq $false} -Server $TARGET

# List users with password never expires
Get-ADUser -Filter {PasswordNeverExpires -eq $true} -Server $TARGET

# List users without Kerberos pre-authentication (ASREPRoastable)
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Server $TARGET

# Using ADSI
$searcher = New-Object System.DirectoryServices.DirectorySearcher
$searcher.SearchRoot = [ADSI]"LDAP://$TARGET/DC=$DOMAIN,DC=local"
$searcher.Filter = "(objectClass=user)"
$searcher.PropertiesToLoad.Add("sAMAccountName") | Out-Null
$searcher.FindAll()

# Using NetExec (if available)
netexec ldap $TARGET -u $USER -p $PASSWORD --users
```

:::

### Group enumeration

::: tabs

=== Unix-like

```bash
# List all groups
ldapsearch -x \
    -H ldap://$TARGET \
    -D "$DOMAIN\\$USER" \
    -w $PASSWORD \
    -b "DC=$DOMAIN,DC=local" \
    "(objectClass=group)" \
    sAMAccountName

# List domain admins
# Note: In environments with localized languages, the CN may differ (e.g., "Administrateurs du domaine" in French)
# This query may fail in non-English environments
ldapsearch -x \
    -H ldap://$TARGET \
    -D "$DOMAIN\\$USER" \
    -w $PASSWORD \
    -b "DC=$DOMAIN,DC=local" \
    "(&(objectClass=group)(cn=Domain Admins))" \
    member

# List group members
ldapsearch -x \
    -H ldap://$TARGET \
    -D "$DOMAIN\\$USER" \
    -w $PASSWORD \
    -b "DC=$DOMAIN,DC=local" \
    "(&(objectClass=group)(cn=GroupName))" \
    member

# Using NetExec
netexec ldap $TARGET -u $USER -p $PASSWORD --groups
```

=== Windows

```powershell
# Using PowerShell with Get-ADGroup (requires RSAT)
Get-ADGroup -Filter * -Server $TARGET

# List Domain Admins group members
Get-ADGroupMember -Identity "Domain Admins" -Server $TARGET

# Using ADSI
$searcher = New-Object System.DirectoryServices.DirectorySearcher
$searcher.SearchRoot = [ADSI]"LDAP://$TARGET/DC=$DOMAIN,DC=local"
$searcher.Filter = "(objectClass=group)"
$searcher.PropertiesToLoad.Add("sAMAccountName") | Out-Null
$searcher.PropertiesToLoad.Add("member") | Out-Null
$searcher.FindAll()

# Using NetExec (if available)
netexec ldap $TARGET -u $USER -p $PASSWORD --groups
```

:::

### Computer enumeration

::: tabs

=== Unix-like

```bash
# List all computers
ldapsearch -x \
    -H ldap://$TARGET \
    -D "$DOMAIN\\$USER" \
    -w $PASSWORD \
    -b "DC=$DOMAIN,DC=local" \
    "(objectClass=computer)" \
    sAMAccountName

# List domain controllers
ldapsearch -x \
    -H ldap://$TARGET \
    -D "$DOMAIN\\$USER" \
    -w $PASSWORD \
    -b "DC=$DOMAIN,DC=local" \
    "(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))" \
    sAMAccountName dNSHostName

# Using NetExec
netexec ldap $TARGET -u $USER -p $PASSWORD --computers
```

=== Windows

```powershell
# Using PowerShell with Get-ADComputer (requires RSAT)
Get-ADComputer -Filter * -Server $TARGET

# List domain controllers (queries the current domain, not necessarily $TARGET)
Get-ADDomainController -Filter *

# Using ADSI
$searcher = New-Object System.DirectoryServices.DirectorySearcher
$searcher.SearchRoot = [ADSI]"LDAP://$TARGET/DC=$DOMAIN,DC=local"
$searcher.Filter = "(objectClass=computer)"
$searcher.PropertiesToLoad.Add("sAMAccountName") | Out-Null
$searcher.FindAll()

# Using NetExec (if available)
netexec ldap $TARGET -u $USER -p $PASSWORD --computers
```

:::

### Password policy

::: tabs

=== Unix-like

```bash
# Get password policy
ldapsearch -x \
    -H ldap://$TARGET \
    -D "$DOMAIN\\$USER" \
    -w $PASSWORD \
    -b "DC=$DOMAIN,DC=local" \
    "(objectClass=domainDNS)" \
    minPwdLength maxPwdAge pwdHistoryLength \
    lockoutThreshold lockoutDuration
```

=== Windows

```powershell
# Using PowerShell with Get-ADDefaultDomainPasswordPolicy (requires RSAT)
Get-ADDefaultDomainPasswordPolicy -Server $TARGET

# Using ADSI
$domain = [ADSI]"LDAP://$TARGET/DC=$DOMAIN,DC=local"
$domain.Properties["minPwdLength"]
$domain.Properties["maxPwdAge"]
$domain.Properties["pwdHistoryLength"]
$domain.Properties["lockoutThreshold"]
$domain.Properties["lockoutDuration"]
```

:::

> [!NOTE]
> The password policy retrieved from the domain object represents the default domain policy. Fine-Grained Password Policies (FGPP) may override the default domain policy for specific users or groups. FGPP policies are stored in `msDS-PasswordSettings` objects and can be queried separately.

### Trust relationships

::: tabs

=== Unix-like

```bash
# List trust relationships with important attributes
ldapsearch -x -H ldap://$TARGET \
  -D "$DOMAIN\\$USER" -w $PASSWORD \
  -b "DC=$DOMAIN,DC=local" \
  "(objectClass=trustedDomain)" \
  trustPartner trustDirection trustAttributes trustType flatName
```

=== Windows

```powershell
# Using PowerShell with Get-ADTrust (requires RSAT)
Get-ADTrust -Filter * -Server $TARGET

# Using ADSI
$searcher = New-Object System.DirectoryServices.DirectorySearcher
$searcher.SearchRoot = [ADSI]"LDAP://$TARGET/DC=$DOMAIN,DC=local"
$searcher.Filter = "(objectClass=trustedDomain)"
$searcher.PropertiesToLoad.Add("trustPartner") | Out-Null
$searcher.PropertiesToLoad.Add("trustDirection") | Out-Null
$searcher.PropertiesToLoad.Add("trustAttributes") | Out-Null
$searcher.PropertiesToLoad.Add("trustType") | Out-Null
$searcher.PropertiesToLoad.Add("flatName") | Out-Null
$searcher.FindAll()
```

:::

> [!NOTE]
> Important attributes for trust relationships include:
> * `flatName` — NetBIOS name of the trusted domain
> * `trustPartner` — FQDN of the trusted domain
> * `trustDirection` — trust direction (inbound, outbound, bidirectional)
> * `trustType` — trust type (Windows, forest, MIT Kerberos, etc.)
> * `trustAttributes` — flags describing transitivity, selective auth, etc.

## Resources

### References

- [RFC 4511 - Lightweight Directory Access Protocol (LDAP): The Protocol](https://www.rfc-editor.org/rfc/rfc4511)
- [RFC 4510 - Lightweight Directory Access Protocol (LDAP): Technical Specification Road Map](https://www.rfc-editor.org/rfc/rfc4510)
- [Microsoft - LDAP Policies](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/how-ldap-authentication-works)
- [Microsoft - RootDSE](https://learn.microsoft.com/en-us/windows/win32/ad/rootdse)
- [OpenLDAP - Administrator's Guide](https://www.openldap.org/doc/admin24/)
- [LDAP Wiki - LDAP Search Best Practices](https://ldapwiki.com/wiki/LDAP%20Search%20Best%20Practices)

### Tools

- [NetExec - LDAP module documentation](https://www.netexec.wiki/)
- [HackTricks - Pentesting LDAP](https://book.hacktricks.xyz/network-services-pentesting/pentesting-ldap)
