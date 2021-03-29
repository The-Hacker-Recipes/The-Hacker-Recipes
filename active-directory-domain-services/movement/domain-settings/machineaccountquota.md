# MachineAccountQuota

## Theory

> MachineAccountQuota \(MAQ\) is a domain level attribute that by default permits unprivileged users to attach up to 10 computers to an Active Directory \(AD\) domain \([source](https://blog.netspi.com/machineaccountquota-is-useful-sometimes/)\)

## Practice

There are multiple ways attackers can leverage that power.

* [Force client authentications](../coerced-authentications/), [relay those authentications](../abusing-lm-and-ntlm/relay.md) to domain controllers using LDAPS, and take advantage of authenticated sessions to create a domain computer account. This account can then be used as a foothold on the AD domain to operate authenticated recon \(i.e. [with BloodHound](../../recon/bloodhound.md) for example\)
* Create a computer account and use it for [Kerberos RBCD attacks](../abusing-kerberos/delegations.md#resource-based-constrained-delegations-rbcd) when leveraging owned accounts with sufficient permissions \(i.e. ACEs like `GenericAll`, `GenericWrite` or `WriteProperty`\) against a target machine
* Create a computer account and use it for a [Kerberos Unconstrained Delegation](../abusing-kerberos/delegations.md#unconstrained-delegations) attack when leveraging owned accounts with sufficient permissions \(i.e. the `SeEnableDelegationPrivilege` user right\)
* Profit from special rights that members of the Domain Computers group could inherit
* Profit from special rights that could automatically be applied to new domain computers based on their account name

### Check the value

{% tabs %}
{% tab title="UNIX-like" %}
The following Python code can be used to check the value of the MachineAccountQuota attribute.

```bash
import ldap3

target_dn = "DC=domain,DC=local" # change this
domain = "domain" # change this
username = "username" # change this
password = "password" # change this

user = "{}\\{}".format(domain, username)
server = ldap3.Server(domain)
connection = ldap3.Connection(server = server, user = user, password = password, authentication = ldap3.NTLM)
connection.bind()
connection.search(target_dn,"(objectClass=*)", attributes=['ms-DS-MachineAccountQuota'])
print(connection.entries[0])
```
{% endtab %}

{% tab title="Windows" %}
In order to run the following commands and tools as other users, testers can check the [user impersonation](../credentials/impersonation.md) part.

The following command, using the [PowerShell ActiveDirectory module](https://docs.microsoft.com/en-us/powershell/module/addsadministration/?view=win10-ps)'s cmdlets Get-ADDomain and Get-ADObject, will help testers make sure the controlled domain user can create computer accounts \(the MachineAccountQuota domain-level attribute needs to be set higher than 0. It is set to 10 by default\).

```bash
Get-ADDomain | Select-Object -ExpandProperty DistinguishedName | Get-ADObject -Properties 'ms-DS-MachineAccountQuota'
```
{% endtab %}
{% endtabs %}

### Create a computer account

{% tabs %}
{% tab title="UNIX-like" %}
The [Impacket](https://github.com/SecureAuthCorp/impacket) script [addcomputer](https://github.com/SecureAuthCorp/impacket/blob/master/examples/addcomputer.py) \(Python\) can be used to create a computer account, using the credentials of a domain user the the MachineAccountQuota domain-level attribute is set higher than 0 \(10 by default\).

```bash
addcomputer.py -computer-name 'SHUTDOWN$' -computer-pass 'SomePassword' -dc-host $DomainController -domain-netbios $DOMAIN 'DOMAIN\anonymous:anonymous'
```

{% hint style="warning" %}
In some mysterious cases, using [addcomputer.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/addcomputer.py) to create a computer account resulted in the creation of a **disabled** computer account. Testers can use [ntlmrelayx](https://github.com/SecureAuthCorp/impacket/blob/master/examples/ntlmrelayx.py) instead with the`--add-computer` option, like [this](https://arkanoidctf.medium.com/hackthebox-writeup-forest-4db0de793f96)
{% endhint %}
{% endtab %}

{% tab title="Windows" %}
The [Powermad](https://github.com/Kevin-Robertson/Powermad) module \(PowerShell\) can be used to create a domain computer account.

```bash
$password = ConvertTo-SecureString 'SomePassword' -AsPlainText -Force
New-MachineAccount -MachineAccount 'PENTEST01' -Password $($password) -Verbose
```

While the machine account can only be deleted by doman administrators, it can be deactivated by the creator account with the following command using the Powermad module.

```bash
Disable-MachineAccount -MachineAccount 'PENTEST01' -Verbose
```
{% endtab %}
{% endtabs %}

{% hint style="info" %}
Testers need to be aware that the MAQ attribute set to a non-zero value doesn't necessarily mean the users can create machine accounts. The right to add workstations to a domain can in fact be changed in the Group Policies. `Group Policy Management Console (gpmc.msc) > Domain Controllers OU > Domain Controllers Policy > Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > User Rights Assigments > Add workstations to domain`
{% endhint %}

## References

{% embed url="https://blog.netspi.com/machineaccountquota-is-useful-sometimes/" %}

{% embed url="https://www.harmj0y.net/blog/activedirectory/the-most-dangerous-user-right-you-probably-have-never-heard-of/" %}

{% embed url="https://social.technet.microsoft.com/wiki/contents/articles/5446.active-directory-how-to-prevent-authenticated-users-from-joining-workstations-to-a-domain.aspx" %}

