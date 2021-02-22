# WPAD spoofing

## Theory

The Web Proxy Automatic Discovery \(WPAD\) protocol allows clients to obtain proxy configurations for Internet access through a `wpad.dat` file hosted on a server which address is usually resolved through DNS. This allows corporations to easily manage web proxy configs through a single file.

## Practice

WPAD spoofing can be combined with 

* [LLMNR and NBT-NS spoofing](llmnr-nbtns-mdns.md)
* [ARP spoofing](arp-poisoning.md) or [DHCPv6 spoofing](dhcpv6-dns-poisoning.md), followed by [DNS spoofing](dns-spoofing.md)

### through LLMNR, NBT-NS spoofing

On old Windows systems \(i.e. lacking the MS16-077 security update\), the WPAD location could be obtained through insecure name resolution protocols like LLMNR and NBT-NS when standard DNS queries were failing \(i.e. no DNS record for WPAD\). This allowed attackers to operate [LLMNR and NBT-NS spoofing](llmnr-nbtns-mdns.md) to answer those WPAD queries and redirect to a fake `wpad.dat` file, hence poisoning the web proxy configuration of the requesting clients, hence obtaining more traffic.

[Responder](https://github.com/SpiderLabs/Responder) \(Python\) and [Inveigh](https://github.com/Kevin-Robertson/Inveigh) \(Powershell\) are great tools for name poisoning. In addition to name poisoning, they also have the ability to start servers \(listeners\) that will [capture authentications](../abusing-lm-and-ntlm/capturing-hashes.md) and echo the NTLM hashes to the attacker.

{% tabs %}
{% tab title="UNIX-like" %}
The following command will start [LLMNR, NBTS and mDNS spoofing](llmnr-nbtns-mdns.md). Name resolution queries for the wpad server will be answered just like any other query. Fake authentication servers \(HTTP/S, SMB, SQL, FTP, IMAP, POP3, DNS, LDAP, ...\) will [capture NTLM hashes](../abusing-lm-and-ntlm/capturing-hashes.md).

* The `--wpad` option will make Responder start the WPAD rogue server so that fake `wpad.dat` file can be served to requesting clients.
* The `--ForceWpadAuth` option is needed on servers that applied the MS16-077 security patch. This patch introduced a mitigation that now prevents clients from automatically authenticating. This option forces the authentication request, hence potentially causing a login prompt.

```bash
responder --interface eth0 --wpad --ForceWpadAuth
```
{% endtab %}

{% tab title="Windows" %}
The following command will start [LLMNR, NBTS and mDNS spoofing](llmnr-nbtns-mdns.md). Name resolution queries for the wpad server will be answered just like any other query. Fake authentication servers \(HTTP/S, SMB, SQL, FTP, IMAP, POP3, DNS, LDAP, ...\) will [capture NTLM hashes](../abusing-lm-and-ntlm/capturing-hashes.md) \(even from machine accounts\) and set the Challenge to `1122334455667788` \(to [crack NTLM hashes](../credentials/cracking.md#practice) with [crack.sh](https://crack.sh/)\).

* Inveigh starts a WPAD rogue proxy server by default.
* Options like `-WPADAuth`, `-WPADAuthIgnore`, `-WPADIP`, `-WPADPort`, `-WPADResponse` \(and others\) can be used to tweak the WPAD abuse.

```text
Invoke-Inveigh -ConsoleOutput Y -LLMNR Y -NBNS Y -mDNS Y -Challenge 1122334455667788 -MachineAccounts Y
```
{% endtab %}
{% endtabs %}

### through ADIDNS spoofing

On up-to-date machines \(i.e. with the MS17-066 security update applied\), WPAD can still be abused through [ADIDNS spoofing](adidns-spoofing.md) if the WPAD record does not exist. There is however a DNS block list mitigation called GQBL \(Global Query Block List\) preventing names like WPAD and ISATAP \(default entries\) to be resolved. This block list exists to reduce vulnerabilities associated with dynamic DNS updates but [it can be edited](https://docs.microsoft.com/en-us/previous-versions/tn-archive/cc995158%28v=technet.10%29) when [implementing WPAD](https://docs.microsoft.com/en-us/previous-versions/tn-archive/cc995261%28v=technet.10%29).

#### Pre CVE-2018-8320

On machines that are not patched against [CVE-2018-8320](https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2018-8320), there are two ways to bypass the GQBL: by [registering a wildcard record](adidns-spoofing.md#manuel-record-addition) or by registering a domain alias \(DNAME\) record, which can be conducted as follows with [Powermad](https://github.com/Kevin-Robertson/Powermad) \(Powershell\).

```bash
New-ADIDNSNode -Node 'pentester01' -Data 'Pentest_IP_Address'
New-ADIDNSNode -Node wpad -Type DNAME -Data 'pentester01.TARGETDOMAIN.LOCAL'
```

#### Post CVE-2018-8320

On machines that are patched against that CVE, registering a name server \(NS\) record could still work. 

```bash
New-ADIDNSNode -Node 'pentester01' -Data 'Pentest_IP_Address'
New-ADIDNSNode -Node wpad -Type NS -Data 'pentester01.TARGETDOMAIN.LOCAL'
```

In order for the NS record technique to work, the tester has to have a DNS server running for [DNS spoofing](dns-spoofing.md). This can easily be accomplished with [dnschef](https://github.com/iphelix/dnschef) \(Python\).

```bash
dnschef --fakeip 'Pentest_IP_Address' --interface 'Pentest_IP_Address' --port 53 --logfile dnschef.log
```

### through DHCPv6 spoofing

On up-to-date machines \(i.e. with the MS17-066 security update applied\), WPAD can still be abused through [ADIDNS spoofing](adidns-spoofing.md), **even if the WPAD record does exist**. With DNS poisoning through DHCPv6 spoofing, an attacker can reply to DHCPv6 requests, and then reply to DNS queries.

This attack can be conducted with [mitm6](https://github.com/fox-it/mitm6) \(Python\), see the [DHCPv6 spoofing](dhcpv6-dns-poisoning.md) page for exploitation notes.

## References

{% embed url="https://blog.netspi.com/adidns-revisited/" %}

{% embed url="https://www.fox-it.com/en/news/blog/mitm6-compromising-ipv4-networks-via-ipv6/" %}



