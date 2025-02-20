---
authors:  AzeTIIx, Jenaye, ShutdownRepo
category: evasion
---

# (AV) Anti-Virus

## Theory

Most of the anti-virus vendors do not communicate much about the rules they put in place to block malicious software. Consequently, there are 3 main possible options to understand the underground process of an anti-virus:

1. reverse the anti-virus binary
2. search on the internet if there are any open source AVs that implement certain rules
3. do regular monitoring

Nevertheless, here is a list of known techniques used by anti-viral protections on the market:

* Static analysis: analysis of instructions and control statements in the code to detect known malware signatures.
* Dynamic analysis: code execution in a virtual environment to detect suspicious behavior.
* Heuristics: analysis of code characteristics to detect suspicious behavior.
* Sandboxing: execution of code in a virtual environment to detect suspicious behavior.
* Signature checking: comparison of suspicious files signature with a database of known malware signatures.
* Fingerprinting: comparison of suspicious files with a database of known malware fingerprints.
* Behavioral check: analysis of suspicious behavior of the executed code.
* Network monitoring: analysis of suspicious network communications.
* URL control: analysis of suspicious URLs.
* File control: analysis of suspicious files.

> [!CAUTION]
> Some AVs have a browser extension that parses the html code for malicious code, be careful during red team operations

> [!TIP]
> Moreover, depending on the anti-virus installed on the victim's computer, it is possible that some techniques do not work and others do.
> 
> Therefore, it is strongly advised to set up a virtual machine as close as possible to the victim's computer.

### Droppers, loaders, stagers, handlers

When working with malwares, the are multiple components that have specific tasks. These components usually allow for better antivirus evasion and/or easier control over the malware's behavior (e.g. being able to control it from a Command & Control).



| Component | Role |
| --- | --- |
| Dropper | Download/deliver a malicious payload to the victim's computer.Once the dropper has successfully installed the malware on the victim's computer, it may also attempt to establish a persistent presence on the system, such as by adding registry entries or creating hidden files. |
| Loader | Load another program or code into memory. Often used to load the main payload of the malware into memory, after which the payload can execute and carry out its activities.Will often implement [process injection](process-injection.md) techniques to inject the malicious code (i.e. shellcode) into a legitimate process running on a victim's system, with the intention of evading antivirus and other security solutions. |
| Stager | Type of loader that loads the main payload of a malware program in multiple stages. Initial stage usually small and responsible for downloading additional stages of the malware from a remote server, or hiding the subsequent stages within the system. |
| Handler | Receive and execute commands from a command and control (C&C) server. |



> [!TIP]
> Simple malwares can sometimes merge the dropper and loader parts into a single piece.

### Staged vs. stageless

Staged malware is like a series of stepping stones where the initial piece of code downloads additional stages of the malware from a remote server. 

Stageless malware, on the other hand, is more of a single file that contains all the malicious code and can execute directly on the victim's computer without needing to download additional stages.

> [!TIP]
> While staged malware is theoretically more likely to be caught, because it consists in more steps and actions than a stageless one, it could be designed in a way that each action appears benign or inconspicuous, hence evading antivirus software.

## Resources

Below is a map listing techniques and tools used for anti-virus evasion. For an interactive view, an [HTML version](https://matro7sh.github.io/BypassAV/) is available (refer to [matro7sh github repository](https://github.com/matro7sh/BypassAV)).

![](<./assets/Bypass-AV.svg>)

AV evasion techniques mindmap{.caption}


[https://evasions.checkpoint.com/](https://evasions.checkpoint.com/)

[https://github.com/matro7sh/BypassAV](https://github.com/matro7sh/BypassAV)