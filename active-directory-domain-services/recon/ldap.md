# LDAP

A lot of information on an AD domain can be obtained through LDAP. Most of the information can only be obtained with an authenticated bind but metadata \(naming contexts, dns server name, domain functional level\) can be obtainable anonymously, even with anonymous binding disabled.

{% tabs %}
{% tab title="ldapsearch-ad" %}
The [ldapsearch-ad](https://github.com/yaap7/ldapsearch-ad) Python script can also be used to enumerate essential information like domain admins that have their password set to never expire, default password policies and the ones found in GPOs, trusts, kerberoastable accounts, and so on.

```bash
ldapsearch-ad --server $DOMAIN_CONTROLLER --domain $DOMAIN --username $USER --password $PASSWORD --type all
```
{% endtab %}

{% tab title="windapsearch" %}
The windapsearch script \([Go](https://github.com/ropnop/go-windapsearch) \(preferred\) or [Python](https://github.com/ropnop/windapsearch)\) can be used to enumerate basic but useful information.

```bash
# enumerate users (authenticated bind)
windapsearch -d $DOMAIN -u $USER -p $PASSWORD --dc $DomainController --module users

# enumerate users (anonymous bind)
windapsearch --dc $DomainController --module users

# obtain metadata (anonymous bind)
windapsearch --dc $DomainController --module metadata
```
{% endtab %}

{% tab title="ldapdomaindump" %}
[ldapdomaindump](https://github.com/dirkjanm/ldapdomaindump) is an Active Directory information dumper via LDAP, outputting information in human-readable HTML files.

```bash
ldapdomaindump --user 'DOMAIN\USER' --password $PASSWORD --outdir ldapdomaindump $DOMAIN_CONTROLLER
```
{% endtab %}
{% endtabs %}

{% hint style="info" %}
LDAP anonymous binding is usually disabled but it's worth checking. It could be handy to list the users and test for [ASREProasting](../movement/abusing-kerberos/asreproast.md) \(since this attack needs no authentication\).
{% endhint %}

{% hint style="success" %}
**Automation and scripting**

* A more advanced LDAP enumeration can be carried out with BloodHound \(see [this](bloodhound.md)\).
* The enum4linux tool can also be used, among other things, for LDAP recon \(see [this page](enum4linux.md)\).
{% endhint %}



