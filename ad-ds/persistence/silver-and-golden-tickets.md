# Silver & Golden tickets

Silver and Golden tickets are forged Kerberos tickets that can be used with [pass-the-ticket](../movement/kerberos/ptt.md) to access services in an Active Directory domain.

* When one of `krbtgt`'s Kerberos keys is known, a [golden ticket](../movement/kerberos/forged-tickets.md#golden-ticket) attack can be conducted to keep privileged access until that account's password is changed.
* Let `service` be an account in charge of various services indicated in its `ServicePrincipalNames` attribute, when one of `service`'s Kerberos keys is known, a [silver ticket](../movement/kerberos/forged-tickets.md#silver-ticket) attack can be conducted to keep privileged access to those managed services until that account's password is changed.

{% content-ref url="../movement/kerberos/forged-tickets.md" %}
[forged-tickets.md](../movement/kerberos/forged-tickets.md)
{% endcontent-ref %}



