# Kerberos

![](<../../../.gitbook/assets/Pass the things.png>)

## Tickets

Kerberos is an authentication protocol based on tickets. It basically works like this (simplified process):

1. Client asks the KDC (Key Distribution Center, usually is a domain controller) for a TGT (Ticket Granting Ticket). One of the requesting user's keys is used for pre-authentication. The TGT is provided by the Authentication Service (AS).
2. Client uses the TGT to ask the KDC for a ST (Service Ticket). That ticket is provided by the Ticket Granting Service (TGS).
3. Client uses the ST (Service Ticket) to access a service
4. Both tickets (TGT and ST) contain the PAC (Privilege Authentication Certificate), a set of information that the target service will read to decide if the authentication user can access the service or not (user ID, group memberships and so on). Only one very special and sensitive service account can write the PAC : `krbtgt`.&#x20;

A Service Ticket (ST) allows access to a specific service. The TGT is used to ask for STs. TGTs can be obtained when supplying a valid secret key. That key can be one of the following (read [more](https://www.sstic.org/media/SSTIC2014/SSTIC-actes/secrets\_dauthentification\_pisode\_ii\_\_kerberos\_cont/SSTIC2014-Article-secrets\_dauthentification\_pisode\_ii\_\_kerberos\_contre-attaque-bordes\_2.pdf)).

| Key name (a.k.a. etype) | Details on key calculation                     |
| ----------------------- | ---------------------------------------------- |
| DES                     | Key derivated from user's password             |
| RC4                     | **Key == NT hash**                             |
| AES128                  | Key derivated from user's password (with salt) |
| AES256                  | Key derivated from user's password (with salt) |

{% hint style="info" %}
By default, the salt is always

* **For users**: uppercase FQDN + case sensitive username = `DOMAIN.LOCALuser`
* **For computers**: uppercase FQDN + `host` + lowercase FQDN hostname without the trailing `$` = `DOMAIN.LOCALhostcomputer.domain.local`

_(_[_Kerberos keys calculation_](https://snovvcrash.rocks/2021/05/21/calculating-kerberos-keys.html)_)_
{% endhint %}

Again, Microsoft has poorly implemented the zero-knowledge proof concept in Kerberos. An attacker knowing a user's NT hash could use it to ask the KDC for a TGT (if RC4 key is accepted). This is called [Overpass-the-hash](ptk.md).

{% content-ref url="ptk.md" %}
[ptk.md](ptk.md)
{% endcontent-ref %}

Users are not the only ones whose NT hashes can be used to abuse Kerberos.

* A TGT is encrypted with the `krbtgt`'s NT hash. An attacker knowing the `krbtgt`'s NT hash can forge TGTs impersonating a domain admin. He can then request STs as a domain admin for any service. The attacker would have access to everything. This forged TGT is called a [Golden ticket](forged-tickets.md#golden-ticket).
* A ST is encrypted with the service account's NT hash. An attacker knowing a service account's NT hash can use it to forge a Service ticket and obtain access to that service. This forged Service ticket is called a [Silver ticket](forged-tickets.md#silver-ticket).

{% content-ref url="forged-tickets.md" %}
[forged-tickets.md](forged-tickets.md)
{% endcontent-ref %}

[Overpass-the-hash](ptk.md), [silver ticket](forged-tickets.md#silver-ticket) and [golden ticket](forged-tickets.md#golden-ticket) attacks are used by attackers to obtain illegitimate tickets that can then be used to access services using Kerberos without knowing any password. This is called [Pass-the-ticket](ptt.md).

{% content-ref url="ptt.md" %}
[ptt.md](ptt.md)
{% endcontent-ref %}

## Roasting

If Kerberos preauthentication is disabled for a user, it is possible to request a TGT for that specific user without knowing any credentials. When the TGT is requested, the KDC sends it along with a session key in the `KRB_AS_REP` message to the requesting client. The session key being encrypted with the requested user's NT hash, it is possible to crack that session key offline in a an attempt to find the user's password. This is called ASREProasting.

{% content-ref url="asreproast.md" %}
[asreproast.md](asreproast.md)
{% endcontent-ref %}

When attackers have a foothold in the domain (i.e. valid domain credentials), they have the (intended) ability to request a service ticket (ST) for any valid SPN (ServicePrincipalName). The ST being encrypted with the service account's NT hash, when that service account's password is weak, it is then possible to crack the ST offline in a an attempt to find the password. This is called Kerberoasting.

{% content-ref url="kerberoast.md" %}
[kerberoast.md](kerberoast.md)
{% endcontent-ref %}

## Delegations

Kerberos delegations allow services to access other services on behalf of domain users. For instance, this allows services to require access to other services' data on the authenticated user's behalf in order to pull data that only the said user is supposed to have access to.

In some situations, Kerberos delegations can be abused by attackers to operate lateral movement or privilege escalation.

{% content-ref url="delegations/" %}
[delegations](delegations/)
{% endcontent-ref %}

In [some cases](delegations/#theory), the delegation will not work. Depending on the context, the [bronze bit ](forged-tickets.md#bronze-bit-cve-2020-17049)vulnerability (CVE-2020-17049) can be used to try to bypass restrictions.

{% content-ref url="forged-tickets.md" %}
[forged-tickets.md](forged-tickets.md)
{% endcontent-ref %}
