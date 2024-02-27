# Diamond tickets

## Theory

[Golden](golden.md) and [Silver tickets](silver.md) can usually be detected by probes that monitor the service ticket requests (`KRB_TGS_REQ`) that have no corresponding TGT requests (`KRB_AS_REQ`). Those types of tickets also feature forged PACs that sometimes fail at mimicking real ones, thus increasing their detection rates. Diamond tickets can be a useful alternative in the way they simply request a normal ticket, decrypt the PAC, modify it, recalculate the signatures and encrypt it again. It requires knowledge of the target service long-term key (can be the `krbtgt` for a TGT, or a target service for a Service Ticket).

## Practice

{% hint style="info" %}
When forging tickets, before November 2021 updates, the user-id and groups-ids were useful but the username supplied was mostly useless. As of Nov. 2021 updates, if the username supplied doesn't exist in Active Directory, the ticket gets rejected. This also applies to Silver Tickets.
{% endhint %}

Since Golden and Silver tickets are fully forged are not preceded by legitimate TGT (`KRB_AS_REQ`) or Service Ticket requests (`KRB_TGS_REQ`), detection rates are quite high. Diamond tickets are an alternative to obtaining similar tickets in a stealthier way.

In this scenario, an attacker that has knowledge of the service long-term key (`krbtgt` keys in case of a TGT, service account keys of Service Tickets) can request a legitimate ticket, decrypt the PAC, modify it, recalculate the signatures and encrypt the ticket again. This technique allows to produce a PAC that is highly similar to a legitimate one and also produces legitimate requests.

{% tabs %}
{% tab title="UNIX-like" %}
From UNIX-like systems, [Impacket](https://github.com/SecureAuthCorp/impacket)'s [ticketer](https://github.com/SecureAuthCorp/impacket/blob/master/examples/ticketer.py) (Python) script can be used for such purposes.

In its actual form (as of September 9th, 2022), the script doesn't modify the PAC in the ticket obtained but instead fully replaces it with a full-forged one. This is not the most stealthy approach as the forged PAC could embed wrong information. Testers are advised to opt for the sapphire ticket approach. On top of that, if there are some structure in the PAC that Impacket can't handle, those structures will be missing in the newly forged PAC.

{% code overflow="wrap" %}
```bash
ticketer.py -request -domain 'DOMAIN.FQDN' -user 'domain_user' -password 'password' -nthash 'krbtgt/service NT hash' -aesKey 'krbtgt/service AES key' -domain-sid 'S-1-5-21-...' -user-id '1337' -groups '512,513,518,519,520' 'baduser'
```
{% endcode %}
{% endtab %}

{% tab title="Windows" %}
From Windows systems, [Rubeus](https://github.com/GhostPack/Rubeus) (C#) can be used for such purposes since [PR#136](https://github.com/GhostPack/Rubeus/pull/136).

{% code overflow="wrap" %}
```batch
Rubeus.exe diamond /domain:DOMAIN /user:USER /password:PASSWORD /dc:DOMAIN_CONTROLLER /enctype:AES256 /krbkey:HASH /ticketuser:USERNAME /ticketuserid:USER_ID /groups:GROUP_IDS
```
{% endcode %}
{% endtab %}
{% endtabs %}

## Resources

{% embed url="https://www.semperis.com/blog/a-diamond-ticket-in-the-ruff/" %}

{% embed url="https://www.trustedsec.com/blog/a-diamond-in-the-ruff/" %}
