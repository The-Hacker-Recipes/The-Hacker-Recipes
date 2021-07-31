# Access Control Entries \(ACEs\)

## Theory

Access privileges for resources in Active Directory Domain Services are usually granted through the use of an Access Control Entry \(ACE\). Access Control Entries describe the allowed and denied permissions for a principal in Active Directory against a securable object \(user, group, computer, container, organization unit \(OU\), GPO and so on\)

DACLs \(Active Directory Discretionary Access Control Lists\) are lists made of ACEs \(Access Control Entries\).

When misconfigured, ACEs can be abused to operate lateral movement or privilege escalation within an AD domain.

## Practice

### Requirements

The attacker needs to be in control of the object the ACE is set on to abuse it and possibly gain control over what this ACE applies to. The following abuses can only be carried out when running commands as the user the ACE is set on \(see [impersonation techniques](../credentials/impersonation.md)\).

### Exploitation paths

In order to navigate the notes, testers can use the mindmap below.

![](../../../.gitbook/assets/abusing-aces.png)

All of the aforementioned attacks \(red blocks\) are detailed in the child notes, except:

* **Shadow Credentials:** see [ADDS &gt; Movement &gt; Kerberos &gt; Shadow Credentials](../kerberos/shadow-credentials.md)
* **Kerberos RBCD**: see [ADDS &gt; Movement &gt; Kerberos &gt; Kerberos Delegations &gt; RBCD](../kerberos/delegations.md#resource-based-constrained-delegations-rbcd)
* **GPO abuses**: see [ADDS &gt; Movement &gt; GPOs](../group-policy-objects.md)
* **DCSync** : see [ADDS &gt; Movement &gt; Credential &gt; Dumping &gt; DCSync](../credentials/dumping/dcsync.md)

{% hint style="success" %}
**Self-attacks**

* User and computers objects can conduct a [Kerberos RCD](../kerberos/delegations.md#resource-based-constrained-delegations-rbcd) attack on themselves.
* Computer objects can conduct a [Shadow Credentials](../kerberos/shadow-credentials.md) attack on themselves.
{% endhint %}

## Resources

{% embed url="https://docs.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights" %}

{% embed url="https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces\#genericall-on-user" caption="" %}

{% embed url="https://wald0.com/?p=112" caption="" %}

{% embed url="http://www.selfadsi.org/deep-inside/ad-security-descriptors.htm" %}

{% embed url="https://adsecurity.org/?p=3658" %}





