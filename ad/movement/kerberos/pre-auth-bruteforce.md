# Pre-auth bruteforce

## Theory

The Kerberos authentication protocol works with tickets in order to grant access. A ST (Service Ticket) can be obtained by presenting a TGT (Ticket Granting Ticket). That prior TGT can only be obtained by validating a first step named "pre-authentication" (except if that requirement is explicitly removed for some accounts, making them vulnerable to [ASREProast](asreproast.md)).

The pre-authentication requires the requesting user to supply its secret key (DES, RC4, AES128 or AES256) derived from his password. An attacker knowing that secret key doesn't need knowledge of the actual password to obtain tickets. This is called [pass-the-key](ptk.md).

Sometimes, the pre-authentication is disabled on some accounts. The attacker can then obtain information encrypted with the account's key. While the obtained TGT cannot be used since it's encrypted with a key the attacker has no knowledge of, the encrypted information can be used to bruteforce the account's password. This is called [ASREProast](asreproast.md).

Last but not least, the pre-authentication step can be bruteforced. This type of [credential bruteforcing](../credentials/bruteforcing/) is way faster and stealthier than other bruteforcing methods relying on NTLM. Pre-authentication bruteforcing can even be faster by using UDP as the transport protocol, hence requiring less frames to be sent.

On a side note, it is possible to enumerate domain users in a similar manner.

## Practice

### Users enum

[nmap](https://nmap.org/)'s `krb5-enum-users` script allows to know wether a username is valid or not (domain-wise) through a legitimate Kerberos service.

{% hint style="info" %}
A TGT request is made through an `AS-REQ` message. When an invalid username is requested, the server will respond using the Kerberos error code `KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN` in the AS-REP message. When working with a valid username, either a TGT will be obtained, or an error like `KRB5KDC_ERR_PREAUTH_REQUIRED` will be raised (i.e. in this case, indicating that the user is required to perform preauthentication).
{% endhint %}

The first step in enumerating the usernames is to create a wordlist (by guessing it or by looking for possible associations on social networks).

```
michael.scott
jim.halpert
oscar.martinez
pam.beesly
kevin.malone
```

The enumeration can then be started.

{% code overflow="wrap" %}
```bash
nmap -p 88 --script="krb5-enum-users" --script-args="krb5-enum-users.realm='$DOMAIN',userdb=$WORDLIST" $IP_DC
```
{% endcode %}

### Pre-auth Bruteforce

Tools like [kerbrute](https://github.com/ropnop/kerbrute) (Go) and [smartbrute](https://github.com/ShutdownRepo/smartbrute) (Python) can be used to bruteforce credentials through the Kerberos pre-authentication. The smartbrute utility can be used in a `brute` mode (standard bruteforcing features) or in a `smart` mode (requires prior knowledge of a low-priv user credentials, but operates LDAP enumeration and avoid locking out accounts, fetches the users list and so on).

```bash
# brute mode, users and passwords lists supplied
smartbrute.py brute -bU $USER_LIST -bP $PASSWORD_LIST kerberos -d $DOMAIN

# smart mode, valid credentials supplied for enumeration
smartbrute.py smart -bP $PASSWORD_LIST ntlm -d $DOMAIN -u $USER -p $PASSWORD kerberos
```

{% hint style="warning" %}
In its default setup, smartbrute will attack Kerberos pre-authentication with the RC4 etype and the UDP transport protocol. While this configuration is the fastest, there are two downsides:

* bruteforcing with the RC4 etype is not the stealthiest option
* using UDP can lead to some support issues. For instance, a valid authentication on a user part of too many groups could raise a `KRB_ERR_RESPONSE_TOO_BIG` error. When an authentication attempt is invalid, a common `KDC_ERR_PREAUTH_FAILED` message should be raised. This allows for bruteforcing, but not authentication.
{% endhint %}

## Resources

{% embed url="https://github.com/ropnop/kerbrute" %}

{% embed url="https://nmap.org/nsedoc/scripts/krb5-enum-users.html" %}
