# 🛠️ Password policy

{% tabs %}
{% tab title="UNIX-like" %}
polenum

```bash
polenum -d $DOMAIN -u $USER -p $PASSWORD -d $DOMAIN
```

crackmapexec

```bash
cme smb $DOMAIN_CONTROLLER -d $DOMAIN -u $USER -p $PASSWORD --pass-pol
```

[ldapsearch-ad](https://github.com/yaap7/ldapsearch-ad) \(Python\)

```bash
ldapsearch-ad.py -l $LDAP_SERVER -d $DOMAIN -u $USER -p $PASSWORD -t pass-pols
```
{% endtab %}

{% tab title="Windows" %}
From domain joined

net accounts
{% endtab %}
{% endtabs %}

If password policy with lockout : bf with sprayhoung, if not bf with kerbrute --&gt; [password guessing](../movement/credentials/bruteforcing/guessing.md) or [stuffing](../movement/credentials/bruteforcing/stuffing.md)

