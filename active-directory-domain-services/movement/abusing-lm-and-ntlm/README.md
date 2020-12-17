# LM and NTLM

{% hint style="danger" %}
A common error people do is mix LM, NT, NTLM, Net-NTLM etc. Let's make things clear. There are **hashing formats** used to store user passwords: LM, NT. And there are **authentication protocols** used to authenticate users to remote resources: LM, NTLM \(v1 and v2\).

* LM hash and NT hash will refer to the hashing formats
* LM, NTLM, NTLMv1, NTLMv2, will refer to the authentication protocols
* LM hash, NTLM hash will refer to the `ChallengeReponse` exchanged during an authentication on LM or NTLM.

Yes, LM hash can either refer to the hashing format used to store user's password, or to the `ChallengeResponse` exchanged during an authentication on the LM protocol. It will depend on the context.

Yes.. this is confusing, but hey go tell this to Microsoft 😤 
{% endhint %}

The LM \(LAN Manager\) and NTLM \(New Technology LM\) authentication protocols are widely used in today's Microsoft environments \(but mostly NTLM\). It relies on a challenge-response scheme based on three messages to authenticate. In order to prove its identity, the authenticating client is asked to compute a `ChallengeResponse` based on multiple variables including:

* a random challenge sent by the server in a `CHALLENGE_MESSAGE`
* a secret key that is the hash of the user's password

The following table details the secret key used by each authentication protocols and the cryptographic algorithm used to compute the `ChallengeResponse` \([source](https://blog.gentilkiwi.com/securite/mimikatz/overpass-the-hash)\).

| Authentication protocol | Algorithm \(for the protocol\) | Secret key |
| :--- | :--- | :--- |
| LM | DES-ECB | LM hash |
| NTLMv1 | DES-ECB | NT hash |
| NTLMv2 | HMAC-MD5 | NT hash |

The following table details the hashing algorithm used by each hashing format in Windows that allows the system to transform the user's password in a non-reversible format.

| Hashing format | Algorithm \(for the hash\) |
| :--- | :--- |
| LM hash | based on DES \([learn more](http://techgenix.com/how-cracked-windows-password-part1/)\) |
| NT hash | MD4 |

This is meant to protect the user's password from eavesdropping by implementing the "zero-knowledge proof" concept. Attackers [capturing authentication](capturing-hashes.md) \(during a man-in-the-middle attack for example\) would not be able to use the `ChallengeResponse` to authenticate. In theory, they could only try to retrieve the user's password from an NTLM hash by operating two expensive \(in time and resources\) [bruteforce attacks](./):

* a bruteforce attack against the LM/NTLM hash \(the `ChallengeResponse`\) to retrieve the LM or NT hash
* if found, a bruteforce/dictionary attack against the NT hash to retrieve the user's password

{% page-ref page="capturing-hashes.md" %}

{% page-ref page="../credentials/cracking.md" %}

The problem is that Microsoft has poorly implemented the zero-knowledge proof concept in the NTLM protocol. The NT hash is used "as is". This means an attacker knowing an NT hash could use it to authenticate as a user without knowing the user's password. This technique is called [Pass the hash](pass-the-hash.md#pass-the-hash-ntlm).

{% page-ref page="pass-the-hash.md" %}

Attackers could also rely on [forced authentications and phishing](../forced-authentications/) to [relay incoming authentications](ntlm-relay.md).

{% page-ref page="../forced-authentications/" %}

{% page-ref page="ntlm-relay.md" %}

