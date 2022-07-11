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

The following table should help  for better understanding of the ACE types and what they allow.

| Common name                    | Permission value / GUID                | Permission type                       | Description                                                                                                                                                                                                         |
| ------------------------------ | -------------------------------------- | ------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| WriteDacl                      | `ADS_RIGHT_WRITE_DAC`                  | Access Right                          | Edit the object's DACL (i.e. "inbound" permissions).                                                                                                                                                                |
| GenericAll                     | `ADS_RIGHT_GENERIC_ALL`                | Access Right                          | Combination of almost all other rights.                                                                                                                                                                             |
| GenericWrite                   | `ADS_RIGHT_GENERIC_WRITE`              | Access Right                          | Combination of write permissions (Self, WriteProperty) among other things.                                                                                                                                          |
| WriteProperty                  | `ADS_RIGHT_DS_WRITE_PROP`              | Access Right                          | Edit one of the object's attributes. The attribute is referenced by an "ObjectType GUID".                                                                                                                           |
| WriteOwner                     | `ADS_RIGHT_WRITE_OWNER`                | Access Right                          | <p>Assume the ownership of the object (i.e. new owner of the victim = attacker, cannot be set to another user). </p><p></p><p>With the "SeRestorePrivilege" right it is possible to specify an arbitrary owner.</p> |
| Self                           | `ADS_RIGHT_DS_SELF`                    | Access Right                          | Perform "Validated writes" (i.e. edit an attribute's value and have that value verified and validate by AD). The "Validated writes" is referenced by an "ObjectType GUID".                                          |
| AllExtendedRights              | `ADS_RIGHT_DS_CONTROL_ACCESS`          | Access Right                          | Peform "Extended rights". "AllExtendedRights" refers to that permission being unrestricted. This right can be restricted by specifying the extended right in the "ObjectType GUID".                                 |
| User-Force-Change-Password     | `00299570-246d-11d0-a768-00aa006e0529` | Control Access Right (extended right) | Change the password of the object without having to know the previous one.                                                                                                                                          |
| DS-Replication-Get-Changes     | `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2` | Control Access Right (extended right) | One of the two extended rights needed to operate a [DCSync](https://www.thehacker.recipes/ad/movement/credentials/dumping/dcsync).                                                                                  |
| DS-Replication-Get-Changes-All | `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2` | Control Access Right (extended right) | One of the two extended rights needed to operate a [DCSync](https://www.thehacker.recipes/ad/movement/credentials/dumping/dcsync).                                                                                  |
| Self-Membership                | `bf9679c0-0de6-11d0-a285-00aa003049e2` | Validate Write                        | Edit the "member" attribute of the object.                                                                                                                                                                          |
| Validated-SPN                  | `f3a64788-5306-11d1-a9c5-0000f80367c1` | Validate Write                        | Edit the "servicePrincipalName" attribute of the object.                                                                                                                                                            |

### Abuse

In order to navigate the notes, testers can use the mindmap below.

![](<../../../.gitbook/assets/DACL abuse.png>)

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
With enough permissions (`GenericAll`, `GenericWrite`) over a disabled object, it is possible to enable it again (e.g. `set-aduser "user" -enabled 1`)
{% endhint %}

## Talk :microphone:

{% embed url="https://youtu.be/_nGpZ1ydzS8" %}

## Resources

{% embed url="https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/990fb975-ab31-4bc1-8b75-5da132cd4584" %}

{% embed url="https://docs.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights" %}

{% embed url="https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces#genericall-on-user" %}

{% embed url="https://wald0.com/?p=112" %}

{% embed url="http://www.selfadsi.org/deep-inside/ad-security-descriptors.htm" %}

{% embed url="https://adsecurity.org/?p=3658" %}

