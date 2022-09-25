# Silver & Golden tickets

Silver, Golden, Diamond and Sapphire tickets are similar variants of forged Kerberos tickets, for different purposes and stealth levels, that can be used with [pass-the-ticket](../movement/kerberos/ptt.md) to access services in an Active Directory domain.

* When one of `krbtgt`'s Kerberos keys is known, a [golden ticket](../movement/kerberos/forged-tickets/golden.md) (or [diamond](../movement/kerberos/forged-tickets/diamond.md), or [sapphire](../movement/kerberos/forged-tickets/sapphire.md)) attack can be conducted to keep privileged access until that account's password is changed.
* Let `service` be an account in charge of various services indicated in its `ServicePrincipalNames` attribute, when one of `service`'s Kerberos keys is known, a [silver ticket](../movement/kerberos/forged-tickets/#silver-ticket) attack can be conducted to keep privileged access to those managed services until that account's password is changed.

{% content-ref url="../movement/kerberos/forged-tickets/" %}
[forged-tickets](../movement/kerberos/forged-tickets/)
{% endcontent-ref %}
