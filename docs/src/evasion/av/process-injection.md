---
description: This technique aims at increasing privilege and/or escaping the protections applied to the processes
authors: Jenaye, ShutdownRepo
category: evasion
---

# 🛠️ Process injection

> [!WARNING]
> This is a work-in-progress. It's indicated with the 🛠️ emoji in the page name or in the category name. Wanna help? Please reach out to me: [@_nwodtuhs](https://twitter.com/_nwodtuhs)

## Theory

Instead of simply executing the shellcode, it has become common to find tricks to hide its active load. The classic schema looks like this:


```
// encrypt the shellcode 
 encrypt(ciphered, SHELLCODE, SHELLCODE_LENGTH, KEY);
// decrypt + handoff 
 decrypt(deciphered, ciphered, SHELLCODE_LENGTH, KEY); 
 handoff(deciphered, SHELLCODE_LENGTH);

```


> After the malicious code is injected into a legitimate process, attackers also can access legitimate processes' resources such as process memory, system/network resources, and elevated privileges 
>
> picussecurity.com

## Practice

Process injection exists in many forms, often based on legitimate services.

The techniques mainly used are : 

* [Process Doppelganging](https://thehackernews.com/2017/12/malware-process-doppelganging.html)
* [Dll injection](https://www.ired.team/offensive-security/code-injection-process-injection/dll-injection)
* [CRT](https://damonmohammadbagher.medium.com/bypassing-anti-virus-by-creating-remote-thread-into-target-process-45f145b2ac7a)

## Resources

all these methods and many others are also described in Ired's article : [https://www.ired.team/offensive-security/code-injection-process-injection](https://www.ired.team/offensive-security/code-injection-process-injection)

[https://www.cyberbit.com/endpoint-security/malware-mitigation-when-direct-system-calls-are-used/](https://www.cyberbit.com/endpoint-security/malware-mitigation-when-direct-system-calls-are-used/)