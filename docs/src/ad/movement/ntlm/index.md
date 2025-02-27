---
authors: AzeTIIx, CryingWelkin, ShutdownRepo, sckdev
category: ad
---

# NTLM

![](<../assets/Pass the things (dark).png>)

## Theory

> [!WARNING]
> A common error people do is mix LM, NT, NTLM, Net-NTLM etc. Let's make things clear. There are hashing formats used to store user passwords: LM, NT. And there are authentication protocols used to authenticate users to remote resources: LM, NTLMv1, and NTLMv2 (
[source](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/network-security-lan-manager-authentication-level)).
> 
> * LM hash and NT hash will refer to the hashing formats
> * LM, NTLM(v1), and NTLMv2, will refer to the authentication protocols
> * LMv1 and LMv2 are response formats that clients return when responding to NTLM_CHALLENGE NTLMv1 and NTLMv2 messages, respectively.
> 
> Yes.. this is confusing, but hey go tell this to Microsoft :triumph:

The LM (LAN Manager) and NTLM (New Technology LM) authentication protocols are widely used in today's Microsoft environments (but mostly NTLM). It relies on a challenge-response scheme based on three messages to authenticate. In order to prove its identity, the authenticating client is asked to compute a response based on multiple variables including:

* a random challenge sent by the server in a `CHALLENGE_MESSAGE`
* a secret key that is the hash of the user's password

The following table details the secret key used by each authentication protocols and the cryptographic algorithm used to compute the response ([source](https://blog.gentilkiwi.com/securite/mimikatz/overpass-the-hash)).

| Authentication protocol | Algorithm (for the protocol) | Secret key |
| ----------------------- | ---------------------------- | ---------- |
| LM | DES-ECB | LM hash |
| NTLM | DES-ECB | NT hash |
| NTLMv2 | HMAC-MD5 | NT hash |

The following table details the hashing algorithm used by each hashing format in Windows that allows the system to transform the user's password in a non-reversible format.

| Hashing format | Algorithm (for the hash) |
| -------------- | ------------------------------------------------------------------------------------- |
| LM hash | based on DES ([learn more](http://techgenix.com/how-cracked-windows-password-part1/)) |
| NT hash | MD4 |

This is meant to protect the user's password from eavesdropping by implementing the "zero-knowledge proof" concept. Attackers [capturing authentication](capture.md) (during a man-in-the-middle attack for example) would not be able to use the response to authenticate. In theory, they could only try to retrieve the user's password from an NTLM hash by operating two expensive (in time and resources) [bruteforce attacks](./):

* a bruteforce attack against the LM/NTLM response to retrieve the LM or NT hash it was derivated from
* if found, a bruteforce/dictionary attack against the NT hash to retrieve the user's password



> [!TIP]
> Read the [capture.md](capture.md) article for more insight


> [!TIP]
> Read the [cracking.md](../credentials/cracking.md) article for more insight


The problem is that Microsoft has poorly implemented the zero-knowledge proof concept in the LM and NTLM protocols. The LM or NT hash is used "as is" to compute the response. This means an attacker knowing an LM or NT hash could use it to authenticate as a user without knowing the user's password. This technique is called [Pass the hash](pth.md).

> [!TIP]
> Read the [pth.md](pth.md) article for more insight


Attackers could also rely on [forced authentications and phishing](../mitm-and-coerced-authentications/index) to [relay incoming authentications](relay.md).

> [!TIP]
> Read the [mitm-and-coerced-authentications](../mitm-and-coerced-authentications/index) article for more insight


> [!TIP]
> Read the [relay.md](relay.md) article for more insight


## Resources

[http://davenport.sourceforge.net/ntlm.html](http://davenport.sourceforge.net/ntlm.html)

[https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/b38c36ed-2804-4868-a9ff-8dd3182128e4](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/b38c36ed-2804-4868-a9ff-8dd3182128e4)

[https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/network-security-lan-manager-authentication-level](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/network-security-lan-manager-authentication-level)
