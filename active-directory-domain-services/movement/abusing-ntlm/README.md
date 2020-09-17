# NTLM

The NTLM authentication protocol is widely used in Microsoft environments. It relies on a challenge-response scheme based on three messages to authenticate. In order to prove its identity, the authenticating client is asked to compute a hash based on multiple variables including:

* a random challenge sent by the server in a `CHALLENGE_MESSAGE`
* the authenticating user's NT hash \(`NThash = MD4(user's password)`\)

This is meant to protect the user's password from eavesdropping by implementing the "zero-knowledge proof" concept. Attackers [capturing an NTLM hash during a man-in-the-middle attack](capturing-hashes.md) would not be able to use it to authenticate. In theory, they could only try to retrieve the user's password from an NTLM hash by operating two expensive \(in time and resources\) [bruteforce attacks](./):

* a bruteforce attack against the NTLM hash to retrieve the NT hash
* if found, a bruteforce/dictionary attack against the NT hash to retrieve the user's password

{% page-ref page="capturing-hashes.md" %}

{% page-ref page="../credentials/cracking.md" %}

The problem is that Microsoft has poorly implemented the zero-knowledge proof concept in the NTLM protocol. The NT hash is used "as is". This means an attacker knowing an NT hash could use it to authenticate as a user without knowing the user's password. This technique is called [Pass the hash](pass-the-hash.md#pass-the-hash-ntlm).

{% page-ref page="pass-the-hash.md" %}

Attackers could also rely on [forced authentications and phishing](../forced-authentications/) to [relay incoming authentications](ntlm-relay.md).

{% page-ref page="../forced-authentications/" %}

{% page-ref page="ntlm-relay.md" %}

