---
description: MITRE ATT&CK™ Sub-technique T1003.003
authors: 'ShutdownRepo, almandin, sckdev'
category: ad
---

# NTDS secrets

NTDS (Windows NT Directory Services) is the directory services used by Microsoft Windows NT to locate, manage, and organize network resources. The NTDS.dit file is a database that stores the Active Directory data (including users, groups, security descriptors and password hashes). This file is stored on the domain controllers.

Once the secrets are extracted, they can be used for various attacks: [credential spraying](../bruteforcing/spraying), [stuffing](../bruteforcing/stuffing.md), [shuffling](../shuffling.md), [cracking](../cracking.md), [pass-the-hash](../../ntlm/pth.md), [overpass-the-hash](../../kerberos/ptk.md) or [silver or golden tickets](../../kerberos/forged-tickets/).

## 1. Exfiltration

Since the NTDS.dit is constantly used by AD processes such as the Kerberos KDC, it can't be copied like any other file. In order to exfiltrate it from a live domain controller and extract password hashes from it, many techniques can be used.

Just like with [SAM & LSA secrets](sam-and-lsa-secrets.md), the SYSTEM registry hive contains enough info to decrypt the NTDS.dit data. The hive file (`\system32\config\system`) can either be exfiltrated the same way the NTDS.dit file is, or it can be exported with `reg save HKLM\SYSTEM 'C:\Windows\Temp\system.save'`.

### AD maintenance (NTDSUtil)

NTDSUtil.exe is a diagnostic tool available as part of Active Directory. It has the ability to save a snapshot of the Active Directory data. Running the following command will copy the NTDS.dit database and the SYSTEM and SECURITY hives to `C:\Windows\Temp`.

```bash
ntdsutil "activate instance ntds" "ifm" "create full C:\Windows\Temp\NTDS" quit quit
```

The following files can then be exported

* `C:\Windows\Temp\NTDS\Active Directory\ntds.dit`
* `C:\Windows\Temp\NTDS\registry\SYSTEM`

> [!WARNING]
> If the NTDS database is very large (several gigabytes), the generation of a defragmented backup with ntdsutil consumes a lot of CPU and disk resources on the server, which can cause slowdowns and other undesirable effects on the domain controller.

### Volume Shadow Copy (VSSAdmin)

VSS (Volume Shadow Copy) is a Microsoft Windows technology, implemented as a service, that allows the creation of backup copies of files or volumes, even when they are in use. The following command will create the shadow copy and will print two values that will be used later: the ID and the Name of the shadow copy.

```bash
vssadmin create shadow /for=C:
```

Once the VSS is created for the target drive, it is then possible to copy the target files from it.

```bash
copy $ShadowCopyName\Windows\NTDS\NTDS.dit C:\Windows\Temp\ntds.dit.save
copy $ShadowCopyName\Windows\System32\config\SYSTEM C:\Windows\Temp\system.save
```

Once the required files are exfiltrated, the shadow copy can be removed

```bash
vssadmin delete shadows /shadow=$ShadowCopyId
```

> [!TIP]
> This attack can be carried out with [Impacket](https://github.com/SecureAuthCorp/impacket/)'s [secretsdump](https://github.com/SecureAuthCorp/impacket/blob/master/examples/secretsdump.py) with the `-use-vss` option. Additionaly, the `-exec-method` option can be set to `smbexec`, `wmiexec` or `mmcexec` to specify on which remote command execution method to rely on for the process.

### NTFS structure parsing

[Invoke-NinjaCopy](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) is a PowerShell script part of the PowerSploit suite able to "copy files off an NTFS volume by opening a read handle to the entire volume (such as c:) and parsing the NTFS structures. This technique is stealthier than the others.

```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\NTDS\NTDS.dit" -LocalDestination "C:\Windows\Temp\ntds.dit.save"
```

## 2. Parsing

Once the required files are exfiltrated, they can be parsed by tools like [secretsdump](https://github.com/SecureAuthCorp/impacket/blob/master/examples/secretsdump.py) (Python, part of [Impacket](https://github.com/SecureAuthCorp/impacket/)) or [gosecretsdump](https://github.com/c-sto/gosecretsdump) (Go, faster for big files).

```bash
secretsdump -ntds ntds.dit.save -system system.save LOCAL
gosecretsdump -ntds ntds.dit.save -system system.save
```

## NTDS Directory parsing and extraction

With the required files, it is possible to extract more information than just secrets. The NTDS file is responsible for storing the entire directory, with users, groups, OUs, trusted domains etc... This data can be retrieved by parsing the NTDS with tools like [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite). With the NTDS alone, objects can be extracted from the NTDS such as user and machine accounts, with a lot of information about them: descriptions, user account control flags, last logon and password change timestamps etc. This information is stored as an SQLite database which is easier to browse and query.

With the `SYSTEM` hive available it is able to extract credentials as well: NT and LM hashes, supplemental credentials such as kerberos keys, cleartext passwords and password hash history.

```bash
ntdsdotsqlite ntds.dit -o ntds.sqlite
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
