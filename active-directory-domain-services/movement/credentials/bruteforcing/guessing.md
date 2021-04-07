---
description: MITRE ATT&CK™ Sub-technique T1110.001
---

# Guessing

## Theory

There are scenarios where testers need to operate credential guessing for lateral movement, privilege escalation, or for obtaining a foothold on a system. Depending on the target user \(or target system\), guessing can be achieved differently.

There are three major types of credential guessing.

* **Common passwords**: a list of common passwords \(admin, backup, qwerty, ...\) are tested against one or more users. This technique is to be used with care since it can cause lockouts and a lot of noise, depending on the target organization's policies.
* **Default passwords**: certain technologies come with default passwords that are often left unchanged. This technique is similar to the "common passwords" technique, but generates less noise and has fewer chances of locking out an account.
* **Situational guessing**: there are many cases where user passwords are not common and yet easily guessable when knowing the organization's vocabulary and context.

## Practice

### Common passwords

Depending on the target service, different lists of common passwords \(e.g. [the SecLists ones](https://github.com/danielmiessler/SecLists/tree/master/Passwords/Common-Credentials)\) and different tools can be used.

* [Hydra](https://github.com/vanhauser-thc/thc-hydra) \(C\) can be used against **a lot \(50+\)** of services like FTP, HTTP, IMAP, LDAP, MS-SQL, MYSQL, RDP, SMB, SSH and many many more.
* [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec) \(Python\) can be used against LDAP, WinRM, SMB, SSH and MS-SQL.
* [Kerbrute](https://github.com/ropnop/kerbrute) \(Go\) can be used against Kerberos pre-authentication \(detailed [here](../../abusing-kerberos/pre-auth-bruteforce.md)\).

{% hint style="info" %}
CrackMapExec has useful options for password guessing

* `--no-bruteforce`: tries user1 -&gt; password1, user2 -&gt; password2 instead of trying every password for every user
* `--continue-on-success`: continues authentication attempts even after successes
{% endhint %}

### Default passwords

This technique can be used with the same tools as the "common passwords" technique but with short and specific password lists. Depending on the number of passwords to try, the bruteforce can be done manually too.

Below are good examples of where to find default passwords

* [SecLists's Default Credentials Sheet](https://github.com/danielmiessler/SecLists/blob/master/Passwords/Default-Credentials/default-passwords.csv) \(for password\)
* [ihebski's DefaultCreds cheatsheet](https://github.com/ihebski/DefaultCreds-cheat-sheet) \(for passwords and SSH keys\)

### Situational guessing

Users are known to be a weak \(if not the weakest\) link of security. Unaware users are known to choose passwords that are easy to remember, hence easy to guess. Below are a few examples that are found to be often used.

* the username
* the name of the company
* the city, or state
* the examples above with transformations \(i.e. numbers and special characters before or after, capital letters, l33tspeak, and so on\)
* a combination of some of the examples above

Testers can try the combinations of user/passwords with the tools mentioned in the "common passwords" technique.

[Sprayhound](https://github.com/Hackndo/sprayhound) \(Python\) is a tool that can dynamically fetch the organization's users and lockout policy to only bruteforce accounts \(against LDAP\) that have a few attempts left in order to avoid locking them out. This can only be done when supplying an Active Directory account's credentials. This tool has the ability to check if accounts have their username set as password. Finally, a great additional feature is that neo4j is supported and compromised accounts can be set as pwned \(useful when working with [BloodHound](../../../recon/bloodhound.md)\).

```bash
# try password equal to the username
sprayhound -d $DOMAIN -dc $DOMAIN_CONTROLLER -lu $LDAP_USER -lp $LDAP_PASSWORD

# try "qwerty" against each user
sprayhound -d $DOMAIN -dc $DOMAIN_CONTROLLER -lu $LDAP_USER -lp $LDAP_PASSWORD -p "qwerty"
```

{% hint style="info" %}
When using this technique, make sure the number of tested users matches the total number of uses on the domain. Dynamically obtaining the users list from a Domain Controller that is not the primary one. 
{% endhint %}

