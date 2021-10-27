# NTLM

![](<../../../.gitbook/assets/Pass the things.png>)

## Theory

{% hint style="danger" %}
A common error people do is mix LM, NT, NTLM, Net-NTLM etc. Let's make things clear. There are **hashing formats** used to store user passwords: LM, NT. And there are **authentication protocols** used to authenticate users to remote resources: LM (v1 or v2), NTLM (v1 or v2).

* LM hash and NT hash will refer to the hashing formats
* LM(v1), LMv2, NTLM(v1), NTLMv2, will refer to the authentication protocols
* LM(v1/v2) and NTLM(v1/v2) response will refer to the secret exchanged during an authentication on LM or NTLM.

Yes.. this is confusing, but hey go tell this to Microsoft :triumph:&#x20;
{% endhint %}

The LM (LAN Manager) and NTLM (New Technology LM) authentication protocols are widely used in today's Microsoft environments (but mostly NTLM). It relies on a challenge-response scheme based on three messages to authenticate. In order to prove its identity, the authenticating client is asked to compute a response based on multiple variables including:

* a random challenge sent by the server in a `CHALLENGE_MESSAGE`
* a secret key that is the hash of the user's password

The following table details the secret key used by each authentication protocols and the cryptographic algorithm used to compute the response ([source](https://blog.gentilkiwi.com/securite/mimikatz/overpass-the-hash)).

| Authentication protocol | Algorithm (for the protocol) | Secret key |
| ----------------------- | ---------------------------- | ---------- |
| LM                      | DES-ECB                      | LM hash    |
| LMv2                    | HMAC-MD5                     | NT hash    |
| NTLM                    | DES-ECB                      | NT hash    |
| NTLMv2                  | HMAC-MD5                     | NT hash    |

The following table details the hashing algorithm used by each hashing format in Windows that allows the system to transform the user's password in a non-reversible format.

| Hashing format | Algorithm (for the hash)                                                              |
| -------------- | ------------------------------------------------------------------------------------- |
| LM hash        | based on DES ([learn more](http://techgenix.com/how-cracked-windows-password-part1/)) |
| NT hash        | MD4                                                                                   |

This is meant to protect the user's password from eavesdropping by implementing the "zero-knowledge proof" concept. Attackers [capturing authentication](capture.md) (during a man-in-the-middle attack for example) would not be able to use the response to authenticate. In theory, they could only try to retrieve the user's password from an NTLM hash by operating two expensive (in time and resources) [bruteforce attacks](./):

* a bruteforce attack against the LM/NTLM response to retrieve the LM or NT hash it was derivated from
* if found, a bruteforce/dictionary attack against the NT hash to retrieve the user's password

{% content-ref url="capture.md" %}
[capture.md](capture.md)
{% endcontent-ref %}

{% content-ref url="../credentials/cracking.md" %}
[cracking.md](../credentials/cracking.md)
{% endcontent-ref %}

The problem is that Microsoft has poorly implemented the zero-knowledge proof concept in the LM and NTLM protocols. The LM or NT hash is used "as is" to compute the response. This means an attacker knowing an LM or NT hash could use it to authenticate as a user without knowing the user's password. This technique is called [Pass the hash](pth.md#pass-the-hash-ntlm).

{% content-ref url="pth.md" %}
[pth.md](pth.md)
{% endcontent-ref %}

Attackers could also rely on [forced authentications and phishing](../mitm-and-coerced-authentications/) to [relay incoming authentications](relay.md).

{% content-ref url="../mitm-and-coerced-authentications/" %}
[mitm-and-coerced-authentications](../mitm-and-coerced-authentications/)
{% endcontent-ref %}

{% content-ref url="relay.md" %}
[relay.md](relay.md)
{% endcontent-ref %}

## Resources

{% embed url="http://davenport.sourceforge.net/ntlm.html" %}
