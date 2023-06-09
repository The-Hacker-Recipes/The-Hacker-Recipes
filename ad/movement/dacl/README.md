# DACL abuse

## Theory

Access privileges for resources in Active Directory Domain Services are usually granted through the use of an Access Control Entry (ACE). Access Control Entries describe the allowed and denied permissions for a principal (e.g. user, computer account) in Active Directory against a securable object (user, group, computer, container, organizational unit (OU), GPO and so on)

DACLs (Active Directory Discretionary Access Control Lists) are lists made of ACEs (Access Control Entries) that identify the users and groups that are allowed or denied access on an object. SACLs (Systems Access Control Lists) define the audit and monitoring rules over a securable object.

When misconfigured, ACEs can be abused to operate lateral movement or privilege escalation within an AD domain.

## Practice

If an object's (called **objectA**) DACL features an ACE stating that another object (called **objectB**) has a specific right (e.g. `GenericAll`) over it (i.e. over **objectA**), attackers need to be in control of **objectB** to take control of **objectA**. The following abuses can only be carried out when running commands as the user mentioned in the ACE (**objectB**) (see [impersonation techniques](../credentials/impersonation.md)).

### Recon

DACL abuse potential paths can be identified by [BloodHound](../../recon/bloodhound.md) from UNIX-like (using the Python ingestor [bloodhound.py](https://github.com/fox-it/BloodHound.py)) and Windows (using the [SharpHound](https://github.com/BloodHoundAD/SharpHound3) ingestor) systems.

Other tools like, `Get-DomainObjectAcl` and `Add-DomainObjectAcl` from [Powersploit](https://github.com/PowerShellMafia/PowerSploit/)'s [Powerview](https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/PowerView.ps1), `Get-Acl` and `Set-Acl` official Powershell cmdlets, or [Impacket](https://github.com/SecureAuthCorp/impacket)'s dacledit.py script (Python) can be used in order to manually inspect an object's DACL. :warning: _At the time of writing, the Pull Request (_[_#1291_](https://github.com/SecureAuthCorp/impacket/pull/1291)_) offering that dacledit is still being reviewed and in active development. It has the following command-line arguments._

### Abuse

In order to navigate the notes, testers can use the mindmap below.

![](<../../../.gitbook/assets/DACL abuse-dark (1).png>)

All of the aforementioned attacks (red blocks) are detailed in the child notes, except:

* **SPN-jacking:** very specific scenario, requires lots of access: see [ADDS > Movement > Kerberos > SPN-jacking](../kerberos/spn-jacking.md)
* **Shadow Credentials:** see [ADDS > Movement > Kerberos > Shadow Credentials](../kerberos/shadow-credentials.md)
* **Kerberos RBCD**: see [ADDS > Movement > Kerberos > Kerberos Delegations > RBCD](../kerberos/delegations/rbcd.md)
* **GPO abuses**: see [ADDS > Movement > GPOs](../group-policies.md)
* **DCSync** : see [ADDS > Movement > Credential > Dumping > DCSync](../credentials/dumping/dcsync.md)

{% hint style="success" %}
**Self-attacks**

* User and computers objects can conduct a [Kerberos RCD](../kerberos/delegations/#resource-based-constrained-delegations-rbcd) attack on themselves.
* Computer objects can conduct a [Shadow Credentials](../kerberos/shadow-credentials.md) attack on themselves.
{% endhint %}

{% hint style="info" %}
**ACE inheritance**

If attacker can write an ACE (`WriteDacl`) for a container or organisational unit (OU), if inheritance flags are added (`0x01+ 0x02`) to the ACE, and inheritance is enabled for an object in that container/OU, the ACE will be applied to it. By default, all the objects with `AdminCount=0` will inherit ACEs from their parent container/OU.

Impacket's dacledit (Python) can be used with the `-inheritance` flag for that purpose ([PR#1291](https://github.com/fortra/impacket/pull/1291)).
{% endhint %}

{% hint style="info" %}
With enough permissions (`GenericAll`, `GenericWrite`) over a disabled object, it is possible to enable it again (e.g. `set-aduser "user" -enabled 1`)
{% endhint %}

### BloodHound ACE edges

[BloodHound](../../recon/bloodhound.md) has the ability to map abuse paths, with some that rely on DACL abuse. The following edges are not includes in the mindmap above:

* `AddKeyCredentialLink`, a write permission on an object's `Key-Credential-Link` attribute, for [Shadow Credentials](../kerberos/shadow-credentials.md) attacks
* `WriteSPN`, a write permission on an object's `Service-Principal-Name` attribute, for [targeted Kerberoasting](targeted-kerberoasting.md) and [SPN jacking](../kerberos/spn-jacking.md) attacks
* `AddSelf`, similar to `AddMember`. While `AddMember` is `WriteProperty` access right on the target's `Member` attribute, `AddSelf` is a `Self` access right on the target's `Member` attribute, allowing the attacker to [add itself to the target group](addmember.md), instead of adding arbitrary principals.
* `AddAllowedToAct`, a write permission on an object's `msDS-Allowed-To-Act-On-Behalf-Of-Other-Identity` attribute, for [Kerberos RBCD](../kerberos/delegations/rbcd.md) attacks
* `SyncLAPSPassword`, both `DS-GetChanges` and `DS-GetChangesInFilteredSet`, for [synchronizing LAPS password](readlapspassword.md) domain-wise
* `WriteAccountRestrictions`, which refers to the `User-Account-Restrictions` property set, which contains enough permissions to modify the `msDS-Allowed-To-Act-On-Behalf-Of-Other-Identity` attribute of the target objects, for [Kerberos RBCD](../kerberos/delegations/rbcd.md) attacks

### Permisssions index

The following table should help  for better understanding of the ACE types and what they allow.

<table><thead><tr><th width="152">Common name</th><th width="205.00141043723553">Permission value / GUID</th><th width="155.47586557018886">Permission type</th><th>Description</th></tr></thead><tbody><tr><td>WriteDacl</td><td><code>ADS_RIGHT_WRITE_DAC</code></td><td>Access Right</td><td>Edit the object's DACL (i.e. "inbound" permissions).</td></tr><tr><td>GenericAll</td><td><code>ADS_RIGHT_GENERIC_ALL</code></td><td>Access Right</td><td>Combination of almost all other rights.</td></tr><tr><td>GenericWrite</td><td><code>ADS_RIGHT_GENERIC_WRITE</code></td><td>Access Right</td><td>Combination of write permissions (Self, WriteProperty) among other things.</td></tr><tr><td>WriteProperty</td><td><code>ADS_RIGHT_DS_WRITE_PROP</code></td><td>Access Right</td><td>Edit one of the object's attributes. The attribute is referenced by an "ObjectType GUID".</td></tr><tr><td>WriteOwner</td><td><code>ADS_RIGHT_WRITE_OWNER</code></td><td>Access Right</td><td><p>Assume the ownership of the object (i.e. new owner of the victim = attacker, cannot be set to another user). </p><p></p><p>With the "SeRestorePrivilege" right it is possible to specify an arbitrary owner.</p></td></tr><tr><td>Self</td><td><code>ADS_RIGHT_DS_SELF</code></td><td>Access Right</td><td>Perform "Validated writes" (i.e. edit an attribute's value and have that value verified and validate by AD). The "Validated writes" is referenced by an "ObjectType GUID".</td></tr><tr><td>AllExtendedRights</td><td><code>ADS_RIGHT_DS_CONTROL_ACCESS</code></td><td>Access Right</td><td>Peform "Extended rights". "AllExtendedRights" refers to that permission being unrestricted. This right can be restricted by specifying the extended right in the "ObjectType GUID".</td></tr><tr><td>User-Force-Change-Password</td><td><code>00299570-246d-11d0-a768-00aa006e0529</code></td><td>Control Access Right (extended right)</td><td>Change the password of the object without having to know the previous one.</td></tr><tr><td>DS-Replication-Get-Changes</td><td><code>1131f6aa-9c07-11d1-f79f-00c04fc2dcd2</code></td><td>Control Access Right (extended right)</td><td>One of the two extended rights needed to operate a <a href="https://www.thehacker.recipes/ad/movement/credentials/dumping/dcsync">DCSync</a>.</td></tr><tr><td>DS-Replication-Get-Changes-All</td><td><code>1131f6ad-9c07-11d1-f79f-00c04fc2dcd2</code></td><td>Control Access Right (extended right)</td><td>One of the two extended rights needed to operate a <a href="https://www.thehacker.recipes/ad/movement/credentials/dumping/dcsync">DCSync</a>.</td></tr><tr><td>Self-Membership</td><td><code>bf9679c0-0de6-11d0-a285-00aa003049e2</code></td><td>Validate Write</td><td>Edit the "member" attribute of the object.</td></tr><tr><td>Validated-SPN</td><td><code>f3a64788-5306-11d1-a9c5-0000f80367c1</code></td><td>Validate Write</td><td>Edit the "servicePrincipalName" attribute of the object.</td></tr></tbody></table>

## Talk :microphone:

{% embed url="https://youtu.be/_nGpZ1ydzS8" %}

## Resources

{% embed url="https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/990fb975-ab31-4bc1-8b75-5da132cd4584" %}

{% embed url="https://docs.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights" %}

{% embed url="https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces#genericall-on-user" %}

{% embed url="http://www.selfadsi.org/deep-inside/ad-security-descriptors.htm" %}

{% embed url="https://adsecurity.org/?p=3658" %}

<details>

<summary>BloodHound releases</summary>

[https://medium.com/@\_wald0/bloodhound-1-3-the-acl-attack-path-update-74aa56c5eb3a](https://medium.com/@\_wald0/bloodhound-1-3-the-acl-attack-path-update-74aa56c5eb3a)

[https://blog.cptjesus.com/posts/bloodhound20/](https://blog.cptjesus.com/posts/bloodhound20/)

[https://posts.specterops.io/introducing-bloodhound-3-0-c00e77ff0aa6](https://posts.specterops.io/introducing-bloodhound-3-0-c00e77ff0aa6)

[https://posts.specterops.io/introducing-bloodhound-4-0-the-azure-update-9b2b26c5e350](https://posts.specterops.io/introducing-bloodhound-4-0-the-azure-update-9b2b26c5e350)

[https://posts.specterops.io/introducing-bloodhound-4-1-the-three-headed-hound-be3c4a808146](https://posts.specterops.io/introducing-bloodhound-4-1-the-three-headed-hound-be3c4a808146)

[https://posts.specterops.io/introducing-bloodhound-4-2-the-azure-refactor-1cff734938bd](https://posts.specterops.io/introducing-bloodhound-4-2-the-azure-refactor-1cff734938bd)

</details>
