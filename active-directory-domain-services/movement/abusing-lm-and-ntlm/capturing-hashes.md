# Capture

## Theory

After successfully [forcing a victim to authenticate](../mitm-and-coerced-authentications/) with LM or NTLM to an attacker's server, the attacker can try to recover credentials by capturing and [cracking the hash](../credentials/cracking.md) \(LM or NTLM hash, a.k.a. ChallengeResponse\) sent by the victim.

## Practice

{% hint style="info" %}
NTLM capture can be combined with any forced authentication attack. Testers should dissociate the name poisoning features that Responder and Inveigh offer from their capturing features. Those tools can be combined with others offering different "authentication forcing" attacks \(like [IPv6 + name poisoning](../mitm-and-coerced-authentications/#ipv6-dns-poisoning), [MS-RPRN abuse](../mitm-and-coerced-authentications/#ms-rprn-abuse) and so on\).
{% endhint %}

[Responder](https://github.com/SpiderLabs/Responder) \(Python\) and [Inveigh](https://github.com/Kevin-Robertson/Inveigh) \(Powershell\) are great tools able to do name poisoning for forced authentication attacks, but also able to capture ChallengeResponses \(LM or NTLM hashes\) by starting servers waiting for incoming authentications. Once those listening servers are up and ready, the tester can initiate the [forced authentication attack](../mitm-and-coerced-authentications/).

{% hint style="info" %}
In order to help the later [cracking process](capturing-hashes.md), testers need to set the NTLM challenge sent to victims to `1122334455667788`.

For Inveigh, it can be defined with a command-line argument. For Responder, testers need to edit the configuration file.

```bash
sed -i 's/ Random/ 1122334455667788/g' /PATH/TO/Responder/Responder.conf
```
{% endhint %}

{% tabs %}
{% tab title="Responder" %}
Start [poisoning LLMNR, NBTNS and mDNS](../mitm-and-coerced-authentications/llmnr-nbtns-mdns.md), enable answers for NetBIOS wredir and domain suffix queries, and try to force LM hashing downgrade \(this will allow to downgrade to the weakest authentication protocol accepted\).

```bash
responder --interface eth0 --wredir --NBTNSdomain --wpad --lm
```

Testers should always try to force a LM hashing downgrade with Responder \(`--lm` option\). LM and NTLMv1 ChallengeResponses \(a.k.a. LM/NTLMv1 hashes\) from Responder can easily be cracked with [crack.sh](https://crack.sh/netntlm/). The [ntlmv1-multi](https://github.com/evilmog/ntlmv1-multi) tool \(Python\) can be used to convert captured `ChallengeResponses` to crackable formats by hashcat, [crack.sh](https://crack.sh/netntlm/) and so on.

```bash
ntlmv1-multi --ntlmv1 SV01$::BREAKING.BAD:AD1235DEAC142CD5FC2D123ADCF51A111ADF45C2345ADCF5:AD1235DEAC142CD5FC2D123ADCF51A111ADF45C2345ADCF5:1122334455667788
```

{% hint style="success" %}
Machine account NT hashes can be used with the [Silver Ticket](../abusing-kerberos/forged-tickets.md#silver-ticket) technique to gain admin access to it.
{% endhint %}
{% endtab %}

{% tab title="Inveigh" %}
Start poisoning LLMNR, NBT-NS and mDNS with a custom challenge, enable HTTPS capturing, enable proxy server authentication captures

```text
Invoke-Inveigh -Challenge 1122334455667788 -ConsoleOutput Y -LLMNR Y -NBNS Y -mDNS Y -HTTPS Y -Proxy Y
```
{% endtab %}
{% endtabs %}

