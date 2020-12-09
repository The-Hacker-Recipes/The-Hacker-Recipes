# Kerberos

## Tickets

Kerberos is an authentication protocol based on tickets. It works like this:

1. Client asks the KDC \(Key Distribution Center, usually is a domain controller\) for a TGT \(Ticket Granting Ticket\). The requesting user's NT hash is used for authentication.
2. Client uses the TGT to ask the KDC for a Service ticket, a.k.a. TGS \(Ticket Granting Service\)
3. Client uses the Service ticket/TGS to access a service

A Service ticket allows access to a specific service. A TGT can be used to access any service/resource the requesting user had the rights to access \(the TGT is used to ask for Service tickets\).

Again, Microsoft has poorly implemented the zero-knowledge proof concept in Kerberos. An attacker knowing a user's NT hash could use it to ask the KDC for a TGT. This is called [Overpass-the-hash](overpass-the-hash.md).

{% page-ref page="overpass-the-hash.md" %}

Users are not the only ones whose NT hashes can be used to abuse Kerberos.

* A TGT is encrypted with the `krbtgt`'s NT hash. An attacker knowing the `krbtgt`'s NT hash can forge TGTs impersonating a domain admin. He can then request TGSs as a domain admin for any service. The attacker would have access to everything. This forged TGT is called a [Golden ticket](silver-and-golden-tickets.md#golden-ticket).
* A TGS is encrypted with the service account's NT hash. An attacker knowing a service account's NT hash can use it to forge a Service ticket and obtain access to that service. This forged Service ticket is called a [Silver ticket](silver-and-golden-tickets.md#silver-ticket).

{% page-ref page="silver-and-golden-tickets.md" %}

[Overpass-the-hash](overpass-the-hash.md), [silver ticket](silver-and-golden-tickets.md#silver-ticket) and [golden ticket](silver-and-golden-tickets.md#golden-ticket) attacks are used by attackers to obtain illegitimate tickets that can then be used to access services using Kerberos without knowing any password. This is called [Pass-the-ticket](pass-the-ticket.md).

{% page-ref page="pass-the-ticket.md" %}

## Roasting

If Kerberos preauthentication is disabled for a user, it is possible to request a TGT for that specific user without knowing any credentials. When the TGT is requested, the KDC sends it along with a session key in the `KRB_AS_REP` message to the requesting client. The session key being encrypted with the requested user's NT hash, it is possible to crack that session key offline in a an attempt to find the user's password. This is called ASREProasting.

{% page-ref page="asreproast.md" %}

When attackers have a foothold in the domain \(i.e. valid domain credentials\), they have the \(intended\) ability to request a service ticket \(TGS\) for any valid SPN \(ServicePrincipalName\). The TGS being encrypted with the service account's NT hash, when that service account's password is weak, it is then possible to crack the TGS offline in a an attempt to find the password. This is called Kerberoasting.

{% page-ref page="kerberoast.md" %}

## Delegations

Kerberos delegations allow services to impersonate users on other services. For instance, this allows services to require access to other services' data on the authenticated user's behalf.

In some situations, Kerberos delegations can be abused by attackers to operate lateral movement or privilege escalation.

{% page-ref page="kerberos-delegations.md" %}

In some situations, Kerberos delegations can't be operated on certains users.The [Bronze bit](silver-and-golden-tickets.md#bronze-bit-cve-2020-17049) vulnerability \(CVE-2020-17049\) introduced the possibility of crafting delegation tickets for protected users. Members of the "Protected users" group are "sensitive and cannot be delegated". For these users, TGS \(service tickets\) come with a "forwardable flag" set to 0 \(False\). This bronze bit vulnerability allows attackers to edit the service ticket's "forwardable" flag and set it to 1 \(True\), hence bypassing the delegation protection for "Protected users" members.

{% page-ref page="silver-and-golden-tickets.md" %}

