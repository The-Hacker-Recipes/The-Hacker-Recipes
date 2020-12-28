---
description: MITRE ATT&CK™ Sub-technique T1110.002
---

# Cracking

## Theory

Attacking Active Directory domains often leads to obtaining password interesting, but either hashed or encrypted data. When these information cannot be directly leveraged for higher privileges \(like with [pass-the-hash](../abusing-lm-and-ntlm/pass-the-hash.md), [overpass-the-hash](../abusing-kerberos/overpass-the-hash.md)\), it is required to crack it.

Cracking is on operation that can be carried out through different types of attacks:

* **Brute-force**: every possibility for a given character set and a given length \(i.e. aaa, aab, aac, ...\) is hashed and compared against the target hash.
* **Dictionary**: every word of a given list \(a.k.a. dictionary\) is hashed and compared against the target hash.
* **Rainbow tables**: the hash is looked for in a precomputed table. It is a [time-memory trade-off](https://en.wikipedia.org/wiki/Space%E2%80%93time_tradeoff) that allows to crack hashes faster, but costing a greater amount of memory that traditional brute-force of dictionary attacks. This attack cannot work if the hashed value is salted \(i.e. hashed with an additionnal random value as prefix/suffix, making the precomputed table irrelevant\)

## Practice

One of the greatest tools that can be used for cracking is [hashcat](https://hashcat.net/hashcat/) \(C\). It implements different types of attacks and many types of hashes. It has many other great features like

* it is cross-platform \(support for Linux, Windows and macOS\) and support anything that comes with an OpenCL runtime \(CPU, GPU, APU, ...\)
* it can crack multiple hashes at the same time and use multiple device at once \(distributed cracking networks supported too\)
* it can save and restore sessions
* it has a builtin benchmarking system

Below is a short list of the most useful hash types for Active Directory hunting.

| Hash type | `-m/--hash-type` number |
| :--- | :--- |
| LM hash | 3000 |
| NT hash | 1000 |
| LM ChallengeResponse | [not supported](https://github.com/hashcat/hashcat/issues/78#issuecomment-276048841) |
| LMv2 ChallengeResponse | [not supported](https://github.com/hashcat/hashcat/issues/78#issuecomment-276048841) |
| NTLM ChallengeResponse | 5500 |
| NTLMv2 ChallengeResponse | 5600 |
| [ASREProast](../abusing-kerberos/asreproast.md) | 13100 |
| [Kerberoast](../abusing-kerberos/kerberoast.md) | 18200 |

Below is an example of how to use hashcat for a dictionary attack.

```bash
hashcat --hash-type $number --attack-mode 0 $hashes_file $wordlist_file
```

Hashcat can also be used in a hybrid mode by combining a dictionary attack with rules that will operate transformations to the words of the list.

* **Great wordlists**: hashesorg2019, TODOTODO
* **Great rules**: oneruletorulethemall, TODOTODO

```bash
hashcat --hash-type $number --attack-mode 0 --rules-file $rules_file $hashes_file $wordlist_file
```

A robust alternative to hashcat is [John the Ripper](https://github.com/openwall/john), a.k.a. john \(C\).

{% hint style="success" %}
**Tips & tricks**

* Google offers services like [Colab](https://colab.research.google.com/) and [Cloud Shell](https://console.cloud.google.com/home/dashboard?cloudshell=true) that can be used for "cloud cracking". There are projects like [penglab](https://github.com/mxrch/penglab), [google-colab-hashcat](https://github.com/ShutdownRepo/google-colab-hashcat) and [cloudtopolis](https://github.com/JoelGMSec/Cloudtopolis) that can help testers to setup a cracking session on such resources
* Other solutions, cloud-based or not, can be used to improve cracking speed: [setting up a rig](https://www.netmux.com/blog/how-to-build-a-password-cracking-rig) for instance.
* LM and NTLM ChallengeResponses can be cracked really fast \(and for free depending on the hash\) on [crack.sh](https://crack.sh/get-cracking/), a remote service that cracks the hash with rainbow tables.
* Testers that manage to pwn a domain admin or a distributed local admin should try to operate multiple [LSASS dumps](dumping/lsass.exe.md) to create a custom wordlist for a dictionary attack
{% endhint %}

