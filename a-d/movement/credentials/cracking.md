---
description: MITRE ATT&CK™ Sub-technique T1110.002
---

# Cracking

## Theory

Attacking Active Directory domains often leads to obtaining password interesting, but either hashed or encrypted data. When this information cannot be directly leveraged for higher privileges (like with [pass-the-hash](../ntlm/pth.md), [overpass-the-hash](../kerberos/ptk.md)), it is required to crack it.

Cracking is an operation that can be carried out through different types of attacks:

* **Brute-force**: every possibility for a given character set and a given length (i.e. `aaa`, `aab`, `aac`, ...) is hashed and compared against the target hash.
* **Dictionary**: every word of a given list (a.k.a. dictionary) is hashed and compared against the target hash.
* **Rainbow tables**: the hash is looked for in a pre-computed table. It is a [time-memory trade-off](https://en.wikipedia.org/wiki/Space%E2%80%93time\_tradeoff) that allows cracking hashes faster, but costing a greater amount of memory than traditional brute-force of dictionary attacks. This attack cannot work if the hashed value is salted (i.e. hashed with an additional random value as prefix/suffix, making the pre-computed table irrelevant)

There are many other and more complex types of attacks (incremental, mask, rules, hybrid types, ...) but the major/core ones are the three above.

## Practice

One of the greatest tools that can be used for cracking is [hashcat](https://hashcat.net/hashcat/) (C). It implements different types of attacks and many types of hashes. It has many other great features like

* it is cross-platform (support for Linux, Windows and macOS) and supports anything that comes with an OpenCL runtime (CPU, GPU, APU, ...)
* it can crack multiple hashes at the same time and use multiple devices at once (distributed cracking networks supported too)
* it can save and restore sessions
* it has a builtin benchmarking system

Below is a short list of the most useful hash types for Active Directory hunting.

| Hash type                                              | `-m/--hash-type` number                                                              |
| ------------------------------------------------------ | ------------------------------------------------------------------------------------ |
| LM hash                                                | 3000                                                                                 |
| NT hash                                                | 1000                                                                                 |
| [LM response](../ntlm/capture.md)                      | [not supported](https://github.com/hashcat/hashcat/issues/78#issuecomment-276048841) |
| [LMv2 response](../ntlm/capture.md)                    | [not supported](https://github.com/hashcat/hashcat/issues/78#issuecomment-276048841) |
| [NTLM response](../ntlm/capture.md)                    | 5500                                                                                 |
| [NTLMv2 response](../ntlm/capture.md)                  | 5600                                                                                 |
| [(DCC1) Domain Cached Credentials](dumping/sam-and-lsa-secrets.md)   | 1100                                                                                 |
| [(DCC2) Domain Cached Credentials 2](dumping/sam-and-lsa-secrets.md) | 2100                                                                                 |
| [ASREQroast](../kerberos/asreqroast.md)                | 7500                                                                                 |
| [ASREProast](../kerberos/asreproast.md)                         | 18200                                                                                |
| [Kerberoast](../kerberos/kerberoast.md)                         | 13100                                                                                |

### Dictionnary attack

Below is an example of how to use hashcat for a dictionary attack.

```bash
hashcat --attack-mode 0 --hash-type $number $hashes_file $wordlist_file
```

### Dictionary and rules attack

{% hint style="success" %}
Hashcat has the ability to inject the plain passwords cracked into the dictionary and start the attack again, and this recursively until no new passwords are found. This can be done with the `--loopback` argument.

_**Nota bene**: the new passwords are added to dictionnary caches that will be temporary and deleted after the bruteforce+rules+loopack attack ends._
{% endhint %}

Hashcat can also be used in a hybrid mode by combining a dictionary attack with rules that will operate transformations to the words of the list.

* **Great wordlists**: [weakpass](https://weakpass.com/), [packetstorm](https://packetstormsecurity.com/Crackers/wordlists/)
* **Great rules**: [pantagrule](https://github.com/rarecoil/pantagrule), [OneRuleToRuleThemAll](https://notsosecure.com/one-rule-to-rule-them-all/)&#x20;

```bash
hashcat --loopback --attack-mode 0 --rules-file $rules_file --hash-type $number $hashes_file $wordlist_file
```

### Brute-force attack

{% hint style="success" %}
**TL; DR**: here is a hashcat command that bruteforces any password from 4 to 8 characters long. Each character can be any printable character.

```bash
hashcat --attack-mode 3 --increment --increment-min 4 --increment-max 8 --hash-type $number $hashes_file "?a?a?a?a?a?a?a?a?a?a?a?a"
```
{% endhint %}

Hashcat has the following built-in charsets that can be used.

```
?l = abcdefghijklmnopqrstuvwxyz
?u = ABCDEFGHIJKLMNOPQRSTUVWXYZ
?d = 0123456789
?s =  !"#$%&'()*+,-./:;<=>?@[\]^_`{|}~
?a = ?l?u?d?s
?b = 0x00 - 0xff
```

Below are examples of hashcat being used with built-in charset.

```bash
# Passwords are like : 1 capital letter, 3 letters, 4 numbers, 1 special char
hashcat --attack-mode 3 --hash-type $number $hashes_file "?u?l?l?l?d?d?d?d?s"

# Password are 8 chars-long and can be any printable char.
hashcat --attack-mode 3 --hash-type $number $hashes_file "?a?a?a?a?a?a?a?a"
```

Hashcat can also be started with custom charsets in the following manner.

```bash
hashcat --attack-mode 3 --custom-charset1 "?u" --custom-charset2 "?l?u?d" --custom-charset3 "?d" --hash-type $number $hashes_file "?1?2?2?2?3"
```

Hashcat also has an incremental feature that allows to bruteforce passwords up to a certain length whereas the commands above only try the specified mask's length.

```bash
# Password are up to 8 chars-long and can be any printable char.
hashcat --attack-mode 3 --increment --hash-type $number $hashes_file "?a?a?a?a?a?a?a?a"

# Password are 4 to 8 chars-long and can be any printable char (mask length is 12 so that --increment-max can be upped to 12).
hashcat --attack-mode 3 --increment --increment-min 4 --increment-max 8 --hash-type $number $hashes_file "?a?a?a?a?a?a?a?a?a?a?a?a"
```

More information on how to fully use hashcat can be found [here](https://www.4armed.com/blog/perform-mask-attack-hashcat/).

### Hashcat alternative

A robust alternative to hashcat is [John the Ripper](https://github.com/openwall/john), a.k.a. john (C). It handles some hash types that hashcat doesn't (Domain Cached Credentials for instance) but it also has a strong community that regularly releases tools in the form of "something2john" that convert things to a john crackable format (e.g. `bitlocker2john`, `1password2john`, `keepass2john`, `lastpass2john` and so on).

## Tips & tricks

{% hint style="success" %}
* Google offers services like [Colab](https://colab.research.google.com/) and [Cloud Shell](https://console.cloud.google.com/home/dashboard?cloudshell=true) that can be used for "cloud cracking". There are projects like [penglab](https://github.com/mxrch/penglab), [google-colab-hashcat](https://github.com/ShutdownRepo/google-colab-hashcat) and [cloudtopolis](https://github.com/JoelGMSec/Cloudtopolis) that can help testers to setup a cracking session on such resources
* Other solutions, cloud-based or not, can be used to improve cracking speed: [setting up a rig](https://www.netmux.com/blog/how-to-build-a-password-cracking-rig) for instance.
* LM and NTLM ChallengeResponses can be cracked really fast (and for free depending on the hash) on [crack.sh](https://crack.sh/get-cracking/), a remote service that cracks the hash with rainbow tables ([here's how to capture those hashes](../ntlm/capture.md#practice)).
* Testers that manage to pwn a domain admin or a distributed local admin should try to operate multiple [LSASS dumps](dumping/lsass.md) to create a custom wordlist for a dictionary attack
* Cracking LM and NT hash can be optimized by following [these advice](https://blog.didierstevens.com/2016/07/25/practice-ntds-dit-file-overview/).
{% endhint %}

{% embed url="https://hashcat.net/wiki/doku.php?id=example_hashes" %}

