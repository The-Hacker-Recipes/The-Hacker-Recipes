# AdminSDHolder

## Theory

AdminSdHolder protects domain objects against permission changes. "AdminSdHolder" either refers to a domain object, a "worker code" or an operation depending on the context.&#x20;

The operation consists in the PDC (Principal Domain Controller) Emulator restoring pre-set permissions for high-privilege users every 60 minutes.

The operation is conducted by a "worker code" called **SDProp** (Security Descriptor propagator).&#x20;

SDProp propagates AdminSdHolder's DACL to every protected object every 60 minutes if their DACL is different.

The AdminSdHolder object is located at `CN=AdminSdHolder,CN=SYSTEM,DC=DOMAIN,DC=LOCAL`. The default AdminSdHolder object's DACL is the following.

* Authenticated Users: **Read**
* SYSTEM: **Full Control**
* Administrators: **Modify**
* Domain Admins: **Modify**
* Enterprise Admins: **Modify**

The default protected objects are the following.

* members (possibly nested) of the following groups: Account Operators Administrator Administrators Backup Operators Domain Admins Domain Controllers Enterprise Admins Print Operators Read-only Domain Controllers Replicator Schema Admins Server Operators
* the `krbtgt` user

{% hint style="info" %}
When talking about AdminSdHolder, the **AdminCount** attribute is usually mentioned. This attribute is automatically set on an object when adding it to a protected group. Originally, the purpose was to improved SDProp's performance. AdminCount cannot be used for malicious purposes and is now mainly informative.
{% endhint %}

## Practice

Once sufficient privileges are obtained, attackers can abuse AdminSdHolder to get persistence on the domain by modifying the object's DACL.&#x20;

Let's say an attackers adds the following ACE to AdminSdHolder's DACL: `attackercontrolleduser: Full Control`.

At the next run of SDProp, `attackercontrolleduser` will have a `GenericAll` privilege over all protected objects (Domain Admins, Domain Controllers, and so on).

This can be done in PowerShell

```
Add-ObjectAcl -TargetADSprefix 'CN=AdminSDHolder,CN=System' -PrincipalSamAccountName spotless -Verbose -Rights All
```

## Resources

{% embed url="https://adsecurity.org/?p=1906" %}

{% embed url="https://docs.microsoft.com/en-us/archive/blogs/askds/five-common-questions-about-adminsdholder-and-sdprop" %}

{% embed url="https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence" %}
