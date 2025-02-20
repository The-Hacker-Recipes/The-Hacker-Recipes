---
description: Lists of techniques used to hide your payload
authors: Jenaye, ShutdownRepo
category: evasion
---

# 🛠️ Obfuscation

> [!WARNING]
> This is a work-in-progress. It's indicated with the 🛠️ emoji in the page name or in the category name. Wanna help? Please reach out to me: [@_nwodtuhs](https://twitter.com/_nwodtuhs)

## Theory

Obfuscation is a way to hide a shellcode. generally symmetric algorithms are used

## Practice

### Manual obfuscation

Below is a list of ways that allow you to go under the radar of anti-virus software, so put all the chances on your side and use several techniques.\
You should also `change the logo` of the binary as well as its `description` and its `creation date` (sandboxes check that the binary is not too recent).

#### Shellcode encoding

For this part the principle is simple: camouflaged its active load, to do this you will need to code a function to encode, but also to decode, free to choose algorithm this technique works particularly well for static bypass.

Here is a link that will allow you to understand and write your first program:

[https://www.ired.team/offensive-security/code-injection-process-injection/writing-custom-shellcode-encoders-and-decoders](https://www.ired.team/offensive-security/code-injection-process-injection/writing-custom-shellcode-encoders-and-decoders)

#### Indirect syscall

the principle of this method is to call directly the memory addresses instead of using the API functions an article which explains things very well is [this one](https://medium.com/@merasor07/av-edr-evasion-using-direct-system-calls-user-mode-vs-kernel-mode-fad2fdfed01a).

#### Delayed execution

In order to compromise the machine discreetly, sleeps are also used a lot, There are several methods: `WaitForSingleObjectEx, Foliage, Ekko, Deathsleep.`

A good part of them are very well explained at the following address : [https://evasions.checkpoint.com/techniques/timing.html#delayed-execution](https://evasions.checkpoint.com/techniques/timing.html#delayed-execution)

#### Disable ETW

There are several ways to disable logging, either via `nt!EtwpStopTrace`, or `advapi32!EventWrite` but also `ntdll!ETWEventWrite.`

To better understand these keywords, I invite you to read this article: [https://www.binarly.io/posts/Design_issues_of_modern_EDRs_bypassing_ETW-based_solutions/index.html](https://www.binarly.io/posts/Design_issues_of_modern_EDRs_bypassing_ETW-based_solutions/index.html).

Another great resource : [https://www.mdsec.co.uk/2020/03/hiding-your-net-etw/](https://www.mdsec.co.uk/2020/03/hiding-your-net-etw/).

### Automatic obfuscation

Depending on your needs, you can use tools available for the most part on github, they are sorted by category below.

:information_source: You can also find all the tools in the mindmap section.

#### Packing

```
- https://github.com/phra/PEzor
- https://github.com/klezVirus/inceptor
- https://github.com/govolution/avet
- https://github.com/Nariod/RustPacker
- https://github.com/DavidBuchanan314/monomorph
- https://github.com/upx/upx

## Office macro
- https://github.com/sevagas/macro_pack
- https://github.com/optiv/Ivy
```

#### AMSI Bypass

```
- https://github.com/CCob/SharpBlock
- https://github.com/danielbohannon/Invoke-Obfuscation
- https://github.com/klezVirus/Chameleon
- https://github.com/tokyoneon/Chimera
```

#### Entropy

[https://github.com/kleiton0x00/Shelltropy](https://github.com/kleiton0x00/Shelltropy)

#### LOLBIN

```
 RemComSvc - https://gist.github.com/snovvcrash/123945e8f06c7182769846265637fedb
```

#### Signature hiding

```
- https://github.com/optiv/ScareCrow
- https://github.com/paranoidninja/CarbonCopy
```



## Resources