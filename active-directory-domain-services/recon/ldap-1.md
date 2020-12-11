# LDAP

A lot of information on an AD domain can be obtained through LDAP. Most of the information can only be obtained with an authenticated bind but metadata \(naming contexts, dns server name, domain functional level\) can be obtainable anonymously, even with anonymous binding disabled.

The tool windapsearch \([Go](https://github.com/ropnop/go-windapsearch) \(preferred\) or [Python](https://github.com/ropnop/windapsearch)\) can be used to enumerate basic but useful information.

```bash
# enumerate users (authenticated bind)
windapsearch -d $DOMAIN -u $USER -p $PASSWORD --dc $DomainController --module users

# enumerate users (anonymous bind)
windapsearch --dc $DomainController --module users

# obtain metadata (anonymous bind)
windapsearch --dc $DomainController --module metadata
```

{% hint style="info" %}
LDAP anonymous binding is usually disabled but it's worth checking. It could be handful to list the users and test for [ASREProasting](../movement/abusing-kerberos/asreproast.md) \(since this attack needs no authentication\).
{% endhint %}

{% hint style="success" %}
A more advanced LDAP enumeration can be carried out with BloodHound \(see [this](ldap.md)\).

Some basic LDAP recon can also be carried out with the enum4linux tool \(see [this page](enum4linux.md)\).
{% endhint %}

