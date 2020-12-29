---
description: MITRE ATT&CK™ Sub-technique T1110.004
---

# 🛠️ Stuffing







### RunAs

^ this link is called in [DCSync](dumping/dcsync.md). I have to move the text from [ACEs abuse](../abusing-aces/) which is :below:

{% hint style="info" %}
The attacker needs to be in control of the object the ACE is set on to abuse it and possibly gain control over what this ACE applies to.

The following abuses can only be carried out when running commands as the user the ACE is set on. On Windows systems, this can be achieved with the following command.

```bash
runas /netonly /user:$DOMAIN\$USER
```

All abuses below can be carried out on a Windows system \(the system doesn't even have to be enrolled in the domain\). 

On UNIX-like systems, a few of the following abuses can be carried out. The [aclpwn](https://github.com/fox-it/aclpwn.py) could maybe do the job in most cases. Personally, I always encountered errors and unsupported operations when trying to use it but I will probably do some further tests to include it here.
{% endhint %}

