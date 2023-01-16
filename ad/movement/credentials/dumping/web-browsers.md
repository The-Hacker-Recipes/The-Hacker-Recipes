---
description: MITRE ATT&CK™ Sub-technique T1555.003
---

# Web browsers

## Theory

Just like other common programs and applications, most web browsers offer "credential saving" features allowing users to access restricted resources without supplying a username and password every time. The downside of this kind of features is that attackers that have access to the storage of these browsers can potentially extract those credentials and use them for credentials [spraying](../bruteforcing/password-spraying.md), [stuffing](../bruteforcing/stuffing.md), and so forth.

## Practice

The [LaZagne](https://github.com/AlessandroZ/LaZagne) (Python) project is a go-to reference from browser credentials dumping (among other awesome dumping features).

```bash
laZagne browsers
```

There are other tools and modules that allow to operate browser credential dumping attacks like metasploit's `post/multi/gather/firefox_creds` and `post/windows/gather/enum_chrome` modules, [firefox decrypt](https://github.com/unode/firefox\_decrypt) (Python) and [chrome decrypter](https://github.com/byt3bl33d3r/chrome-decrypter) (Python). On Windows systems, browsers like Chrome, Brave and Opera rely on Windows's DPAPI to store credentials. [Mimikatz](https://github.com/gentilkiwi/mimikatz) (C) can then be used (e.g. [`dpapi::chrome`](https://tools.thehacker.recipes/mimikatz/modules/dpapi/chrome)).

## Resources

{% embed url="https://github.com/AlessandroZ/LaZagne" %}
