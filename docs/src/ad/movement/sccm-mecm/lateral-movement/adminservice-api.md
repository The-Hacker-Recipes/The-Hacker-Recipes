---
authors: BlWasp, ShutdownRepo, felixbillieres
category: ad
---

# AdminService API

## Theory

It appears that, with SCCM administrative rights, it is possible to directly interact with the AdminService API, without using CMPivot, for post SCCM exploitation purpose.

> [!TIP]
> For additional attack techniques and defense strategies related to AdminService API abuse in SCCM, refer to the following techniques from the [Misconfiguration-Manager repository](https://github.com/subat0mik/Misconfiguration-Manager/tree/main/attack-techniques):
> - [RECON-4: CMPivot](https://github.com/subat0mik/Misconfiguration-Manager/blob/main/attack-techniques/RECON/RECON-4/recon-4_description.md)
> - [RECON-5: SMS Provider Enumeration](https://github.com/subat0mik/Misconfiguration-Manager/blob/main/attack-techniques/RECON/RECON-5/recon-5_description.md)
> - [CRED-7: AdminService API Credentials](https://github.com/subat0mik/Misconfiguration-Manager/blob/main/attack-techniques/CRED/CRED-7/cred-7_description.md)

## Practice

::: tabs

=== UNIX-like

From UNIX-like systems, [sccmhunter](https://github.com/garrettfoster13/sccmhunter) (Python) can be used for this purpose.

```bash
sccmhunter.py admin -u "$USER" -p "$PASSWORD" -ip "site_server_IP"
```

Then, the `help` command can be typed in the opened shell to view all the CMPivot commands handled by [sccmhunter](https://github.com/garrettfoster13/sccmhunter).

```
() C:\ >> help

Documented commands (use 'help -v' for verbose/'help ' for details):

Database Commands
=================
get_collection get_device get_lastlogon get_puser get_user

Interface Commands
==================
exit interact

PostEx Commands
===============
add_admin backdoor backup delete_admin restore script

Situational Awareness Commands
==============================
administrators console_users ipconfig osinfo sessions
cat disk list_disk ps shares 
cd environment ls services software
```

=== Windows

From Windows systems, [SharpSCCM](https://github.com/Mayyhem/SharpSCCM) (C#) can be used for this purpose.

**Step 1**: retrieve the ID of the resource to enumerate (a computer or a computer collection)

```powershell
SharpSCCM.exe get resource-id -d "COMPUTER"
```

---
**Step 2**: execute administrative tasks with CMPivot requests

```powershell
# Enumerate the local administrators
SharpSCCM.exe invoke admin-service -r $RESOURCE_ID -q "Administrators" -j

# Enumerate the installed softwares
SharpSCCM.exe invoke admin-service -r $RESOURCE_ID -q "InstalledSoftware" -j
```

Instructions about how to write CMPivot queries are presented [here](https://learn.microsoft.com/fr-fr/mem/configmgr/core/servers/manage/cmpivot).

:::

## Resources

[https://learn.microsoft.com/fr-fr/mem/configmgr/core/servers/manage/cmpivot](https://learn.microsoft.com/fr-fr/mem/configmgr/core/servers/manage/cmpivot)

[https://github.com/subat0mik/Misconfiguration-Manager/tree/main/attack-techniques/RECON](https://github.com/subat0mik/Misconfiguration-Manager/tree/main/attack-techniques/RECON)

[https://github.com/subat0mik/Misconfiguration-Manager/blob/main/attack-techniques/CRED/CRED-7/cred-7_description.md](https://github.com/subat0mik/Misconfiguration-Manager/blob/main/attack-techniques/CRED/CRED-7/cred-7_description.md)

