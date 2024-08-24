# Password policy

When attacking Active Directory domains, directly targeting accounts is usually a great start. It could provide initial access and help the attackers operate lateral movement. The easiest way to compromise accounts is to operate some password [bruteforcing](../movement/credentials/bruteforcing/), [guessing](../movement/credentials/bruteforcing/guessing.md) or [spraying](../movement/credentials/bruteforcing/password-spraying.md). This kind of attack usually yields good results depending on the user's awareness. There are however technical measures that usually are in place, forcing the attackers to balance the number and speed of password attempts.

In order to fine-tune this, the password policy can be obtained. This policy can sometimes be enumerated with a null-session \(i.e. an [MS-RPC null session](ms-rpc.md#null-sessions) or an [LDAP anonymous bind](ldap.md)\).

{% tabs %}
{% tab title="UNIX-like" %}
On UNIX-like systems, there are many alternatives that allow obtaining the password policy like [polenum](https://github.com/Wh1t3Fox/polenum) \(Python\), [NetExec](https://github.com/Pennyw0rth/NetExec) \(Python\), [ldapsearch-ad](https://github.com/yaap7/ldapsearch-ad) \(Python\) and [enum4linux](enum4linux.md).

```bash
# polenum (obtained through MS-RPC)
polenum -d $DOMAIN -u $USER -p $PASSWORD -d $DOMAIN

# netexec (obtained through MS-RPC)
nxc smb $DOMAIN_CONTROLLER -d $DOMAIN -u $USER -p $PASSWORD --pass-pol

# ldapsearch-ad (obtained through LDAP)
ldapsearch-ad.py -l $LDAP_SERVER -d $DOMAIN -u $USER -p $PASSWORD -t pass-pol

# enum4linux-ng (obtained through MS-RPC)
enum4linux-ng -P -w -u $USER -p $PASSWORD $DOMAIN_CONTROLLER 
```
{% endtab %}

{% tab title="Windows" %}
From a domain-joined machine, the `net` cmdlet can be used to obtain the password policy.

```bash
net accounts
net accounts /domain
```

From non-domain-joined machines, it can be done with [PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1) \(Powershell\).

```bash
Get-DomainPolicy
```
{% endtab %}
{% endtabs %}

{% hint style="info" %}
Accounts that lockout can be attacked with [sprayhound](https://github.com/Hackndo/sprayhound) \([credential spraying](../movement/credentials/bruteforcing/password-spraying.md)\) while those that don't can be directly bruteforced with [kerbrute](https://github.com/ropnop/kerbrute) \([Kerberos pre-auth bruteforcing](../movement/kerberos/pre-auth-bruteforce.md)\)
{% endhint %}

