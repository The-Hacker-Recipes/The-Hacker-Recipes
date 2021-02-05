# Kerberos

## Tickets

Kerberos is an authentication protocol based on tickets. It basically works like this \(simplified process\):

1. Client asks the KDC \(Key Distribution Center, usually is a domain controller\) for a TGT \(Ticket Granting Ticket\). The requesting user's NT hash is used for authentication.
2. Client uses the TGT to ask the KDC for a Service ticket, a.k.a. TGS \(Ticket Granting Service\)
3. Client uses the Service ticket/TGS to access a service

A Service ticket \(TGS\) allows access to a specific service. The TGT is used to ask for TGSs. TGTs can be obtained when supplying a valid secret key. That key can be one of the following \(read [more](https://www.sstic.org/media/SSTIC2014/SSTIC-actes/secrets_dauthentification_pisode_ii__kerberos_cont/SSTIC2014-Article-secrets_dauthentification_pisode_ii__kerberos_contre-attaque-bordes_2.pdf)\).

| Key name \(a.k.a. etype\) | Details on key calculation |
| :--- | :--- |
| DES | Key derivated from user's password \(DOMAINusername as salt\) |
| RC4 | **Key is NT hash** |
| AES128 | Key derivated from user's password \(DOMAINusername as salt\) |
| AES256 | Key derivated from user's password \(DOMAINusername as salt\) |

Again, Microsoft has poorly implemented the zero-knowledge proof concept in Kerberos. An attacker knowing a user's NT hash could use it to ask the KDC for a TGT \(if RC4 key is accepted\). This is called [Overpass-the-hash](overpass-the-hash.md).

{% page-ref page="overpass-the-hash.md" %}

Users are not the only ones whose NT hashes can be used to abuse Kerberos.

* A TGT is encrypted with the `krbtgt`'s NT hash. An attacker knowing the `krbtgt`'s NT hash can forge TGTs impersonating a domain admin. He can then request TGSs as a domain admin for any service. The attacker would have access to everything. This forged TGT is called a [Golden ticket](forged-tickets.md#golden-ticket).
* A TGS is encrypted with the service account's NT hash. An attacker knowing a service account's NT hash can use it to forge a Service ticket and obtain access to that service. This forged Service ticket is called a [Silver ticket](forged-tickets.md#silver-ticket).

{% page-ref page="forged-tickets.md" %}

[Overpass-the-hash](overpass-the-hash.md), [silver ticket](forged-tickets.md#silver-ticket) and [golden ticket](forged-tickets.md#golden-ticket) attacks are used by attackers to obtain illegitimate tickets that can then be used to access services using Kerberos without knowing any password. This is called [Pass-the-ticket](pass-the-ticket.md).

{% page-ref page="pass-the-ticket.md" %}

## Roasting

If Kerberos preauthentication is disabled for a user, it is possible to request a TGT for that specific user without knowing any credentials. When the TGT is requested, the KDC sends it along with a session key in the `KRB_AS_REP` message to the requesting client. The session key being encrypted with the requested user's NT hash, it is possible to crack that session key offline in a an attempt to find the user's password. This is called ASREProasting.

{% page-ref page="asreproast.md" %}

When attackers have a foothold in the domain \(i.e. valid domain credentials\), they have the \(intended\) ability to request a service ticket \(TGS\) for any valid SPN \(ServicePrincipalName\). The TGS being encrypted with the service account's NT hash, when that service account's password is weak, it is then possible to crack the TGS offline in a an attempt to find the password. This is called Kerberoasting.

{% page-ref page="kerberoast.md" %}

## Delegations

Kerberos delegations allow services to impersonate users on other services. For instance, this allows services to require access to other services' data on the authenticated user's behalf.

In some situations, Kerberos delegations can be abused by attackers to operate lateral movement or privilege escalation.

{% page-ref page="delegations.md" %}

In [some cases](delegations.md#theory), the delegation will not work. Depending on the context, the [bronze bit ](forged-tickets.md#bronze-bit-cve-2020-17049)vulnerability \(CVE-2020-17049\) can be used to try to bypass restrictions.

{% page-ref page="forged-tickets.md" %}

