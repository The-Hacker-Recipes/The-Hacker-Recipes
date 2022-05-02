# Access controls

## Theory

Access privileges for resources in Active Directory Domain Services are usually granted through the use of an Access Control Entry (ACE). Access Control Entries describe the allowed and denied permissions for a principal (e.g. user, computer account) in Active Directory against a securable object (user, group, computer, container, organizational unit (OU), GPO and so on)

DACLs (Active Directory Discretionary Access Control Lists) are lists made of ACEs (Access Control Entries) that identify the users and groups that are allowed or denied access on an object. SACLs (Systems Access Control Lists) define the audit and monitoring rules over a securable object.

When misconfigured, ACEs can be abused to operate lateral movement or privilege escalation within an AD domain.

## Practice

If an object's (called **objectA**) DACL features an ACE stating that another object (called **objectB**) has a specific right (e.g. `GenericAll`) over it (i.e. over **objectA**), attackers need to be in control of **objectB** to take control of **objectA**. The following abuses can only be carried out when running commands as the user mentioned in the ACE (**objectB**) (see [impersonation techniques](../credentials/impersonation.md)).

### Recon

ACE abuse potential paths can be identified by [BloodHound](../../recon/bloodhound.md) from UNIX-like (using the Python ingestor [bloodhound.py](https://github.com/fox-it/BloodHound.py)) and Windows (using the [SharpHound](https://github.com/BloodHoundAD/SharpHound3) ingestor) systems.

### Abuse

In order to navigate the notes, testers can use the mindmap below.

![](<../../../.gitbook/assets/Access Control Entries.png>)

All of the aforementioned attacks (red blocks) are detailed in the child notes, except:

* **SPN-jacking:** very specific scenario, requires lots of access: see [ADDS > Movement > Kerberos > SPN-jacking](../kerberos/spn-jacking.md)
* **Shadow Credentials:** see [ADDS > Movement > Kerberos > Shadow Credentials](../kerberos/shadow-credentials.md)
* **Kerberos RBCD**: see [ADDS > Movement > Kerberos > Kerberos Delegations > RBCD](../kerberos/delegations/#resource-based-constrained-delegations-rbcd)
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

{% embed url="https://docs.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights" %}

{% embed url="https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces#genericall-on-user" %}

{% embed url="https://wald0.com/?p=112" %}

{% embed url="http://www.selfadsi.org/deep-inside/ad-security-descriptors.htm" %}

{% embed url="https://adsecurity.org/?p=3658" %}



