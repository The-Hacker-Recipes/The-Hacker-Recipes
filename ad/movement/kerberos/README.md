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

* A TGT is encrypted with the `krbtgt`'s NT hash. An attacker knowing the `krbtgt`'s NT hash can forge TGTs impersonating a domain admin. He can then request STs as a domain admin for any service. The attacker would have access to everything. This forged TGT is called a [Golden ticket](forged-tickets/golden.md).
* A ST is encrypted with the service account's NT hash. An attacker knowing a service account's NT hash can use it to forge a Service ticket and obtain access to that service. This forged Service ticket is called a [Silver ticket](forged-tickets/silver.md).

{% content-ref url="forged-tickets/" %}
[forged-tickets](forged-tickets/)
{% endcontent-ref %}

[Overpass-the-hash](ptk.md), [silver ticket](forged-tickets/#silver-ticket) and [golden ticket](forged-tickets/#golden-ticket) attacks are used by attackers to obtain illegitimate tickets that can then be used to access services using Kerberos without knowing any password. This is called [Pass-the-ticket](ptt.md).

{% content-ref url="ptt.md" %}
[ptt.md](ptt.md)
{% endcontent-ref %}

## Roasting

If Kerberos preauthentication is disabled for a user, it is possible to request a TGT for that specific user without knowing any credentials. When the TGT is requested, the KDC sends it along with a session key in the `KRB_AS_REP` message to the requesting client. The session key being encrypted with the requested user's NT hash, it is possible to crack that session key offline in a an attempt to find the user's password. This is called ASREProasting.

{% content-ref url="asreproast.md" %}
[asreproast.md](asreproast.md)
{% endcontent-ref %}

If an attacker finds himself in a man-in-the-middle position, effectively capturing Kerberos messages, he could capture `KRB_AS_REQ` messages and operate a similar cracking attempt.

{% content-ref url="asreqroast.md" %}
[asreqroast.md](asreqroast.md)
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

In [some cases](delegations/#theory), the delegation will not work. Depending on the context, the [bronze bit ](forged-tickets/#bronze-bit-cve-2020-17049)vulnerability (CVE-2020-17049) can be used to try to bypass restrictions.

{% content-ref url="delegations/bronze-bit.md" %}
[bronze-bit.md](delegations/bronze-bit.md)
{% endcontent-ref %}

## Service-for-User extensions

Kerberos delegations can be abused by attackers to obtain access to valuable assets and sometimes even escalate to domain admin privileges. Regarding [constrained delegations](delegations/constrained.md) and [rbcd](delegations/rbcd.md), those types of delegation rely on Kerberos extensions called S4U2Self and S4U2Proxy.

* **Service for User to Self (S4U2self)**: allows a service to obtain a Service Ticket, on behalf of another user (called "principal"), to itself.&#x20;

<details>

<summary>S4U2self requirements</summary>

This extension can only be used by an account that has at least one SPN (except if S4U2self is combined with [U2U](./#user-to-user-authentication)).

The resulting Service Ticket is `forwardable` (i.e. can be used with S4U2Proxy to access another service) if and only if:

* the service is configured for **constrained delegation (KCD)** **with protocol transition**
* the principal is **not "sensitive for delegation"**
* the principal is **not a member of the Protected Users** group

</details>

* **Service for User to Proxy (S4U2proxy)**: allows a service to obtain a Service Ticket, on behalf of a user to a different service.&#x20;

<details>

<summary>S4U2proxy requirements</summary>

For this extension to work properly, the service needs to supply a Service Ticket as "additional-ticket" (i.e. used as an evidence that the service using S4U2proxy has the authority to do it on behalf of a user).

For an S4U2proxy request to work and have the KDC issue a Service Ticket:

* the ST used as "additional-ticket" must have the **forwardable** flag set.
* alternatively, in the `TGS-REQ`, in the pre-authentication data, the `PA-PAC-OPTIONS` structure must contain a padata value with the resource-based constrained delegation bit set ([doc](https://docs.microsoft.com/en-us/openspecs/windows\_protocols/ms-sfu/aeecfd82-a5e4-474c-92ab-8df9022cf955)).\
  _nota bene 1: this only applies if the **resource-based constrained delegation (RBCD)** is actually possible and authorized in the proper AD objects attributes._\
  _nota bene 2: Rubeus and Impacket's getST always set that bit when doing S4U2proxy._

On a side note, S4U2Proxy always results in a forwardable ST, even when the ticket used as evidence wasn't forwardable.

</details>

<details>

<summary>More technical notes</summary>

S4U2self and S4U2proxy are variations of Service Ticket requests (`KRB_TGS_REQ`). Below is what differentiates a S4U2self from a S4U2proxy from a standard `KRB_TGS_REQ`.​

* **S4U2self**
  * Request contains a `PA-FOR-USER` padata type structure containing the name and the realm of the user to impersonate ([doc](https://docs.microsoft.com/en-us/openspecs/windows\_protocols/ms-sfu/aceb70de-40f0-4409-87fa-df00ca145f5a)).
  * the `cname` (user name authenticating) and the `sname` (service name being requested) are the same. In order to succeed and not have the KDC throw an `KDC_ERR_S_PRINCIPAL_UNKNOWN`, the `sname` should refer to an account that has at least one SPN (`Service Principal Name`) set.
* **S4U2proxy**
  * Request contains an `additional-tickets` field containing a service ticket. In order to succeed and not have the KDC throw an `KDC_ERR_BADOPTION`, the ticket should have the `forwardable` flag set. In a standard constrained delegation or rbcd scenario, the ticket added in the `additional-tickets` field is the one obtained through S4U2self.
  * Request contains the `CNAME-IN-ADDL-TKT` flag in the `kdc-options` field, indicating S4U2proxy is used ([doc](https://docs.microsoft.com/en-us/openspecs/windows\_protocols/ms-sfu/17b9af82-d45a-437d-a05c-79547fe969f5)).

</details>

## User-to-User authentication

U2U has nothing to do with S4U mechanisms and plays no part in delegation internals.

> \[U2U] allows users to host secure application services on their desktop machines. \[...] In the user-to-user protocol, one user acts as a server, and the other user acts as a client. ([Frequently Asked Questions about Kerberos](http://www.di-srv.unisa.it/\~ads/corso-security/www/CORSO-0001/kerberos/ref/kerberos-faq.html#u2uauth)).

<details>

<summary>More technical notes</summary>

A U2U request is a variation of a common Service Ticket request (`KRB_TGS_REQ`). Below is what differentiates a U2U from a standard `KRB_TGS_REQ`. It allows a user to request a service ticket to another user.

* Request contains an `additional-tickets` field containing the target user TGT.
* Request contains the `ENC-TKT-IN-SKEY` flag in the `kdc-options` field, indicating that the ticket for the end server is to be encrypted in the session key from the additional TGT provided ([doc](https://docs.microsoft.com/en-us/openspecs/windows\_protocols/ms-sfu/17b9af82-d45a-437d-a05c-79547fe969f5)).
* The `sname` refers to a UPN (`User Principal Name`) of an account that doesn't necessarily have to have an SPN set.

</details>

<details>

<summary>S4U2self + U2U</summary>

In some specific scenarios, S4U2self and U2U can be combined, in which case the flags and structures bot mechanisms include in their requests are combined.

This allows to

* operate [RBCD attacks from SPN-less accounts](delegations/rbcd.md#rbcd-on-spn-less-users)
* operate an [unPAC-the-hash](unpac-the-hash.md) attack
* retrieve and decrypt the PAC (Privileged Attribute Certificate) of any account. Could be used to obtain a [sapphire ticket](forged-tickets/).

</details>
