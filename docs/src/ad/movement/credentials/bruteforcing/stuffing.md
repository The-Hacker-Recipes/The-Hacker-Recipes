---
description: MITRE ATT&CK™ Sub-technique T1110.004
authors: ShutdownRepo, sckdev
category: ad
---

# Stuffing

When credentials are found (through [dumping](../dumping/index) or [cracking](../cracking.md) for instance), attackers can try to use them to obtain access on other accounts. This attacks can be powerful against organizations that use shared or common passwords. 

This technique can be combined with [credential guessing](guessing.md) when attackers try to operate transformations to the recovered passwords (i.e. numbers and special characters before or after, capital letters, l33tspeak, and so on). These new password lists can even be used in an additional [cracking](../cracking.md) process.

> [!TIP]
> [The same tools](guessing.md#common-passwords) used for guessing can be used for stuffing and guessing.