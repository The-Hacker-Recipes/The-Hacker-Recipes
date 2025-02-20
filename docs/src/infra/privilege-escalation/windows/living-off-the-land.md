---
authors: ShutdownRepo
category: infra
---

# 🛠️ Living off the land

## Theory

Living of the Land is a well known privilege escalation technique, where an attacker will leverage binaries found on the attacked machine to perform a privilege escalation. Indeed, many UNIX programs have options that can be exploited to open a shell. Therefore if we can start the program we exploit as another user, we might be able to open a shell as this user ! 

Most of the payloads to do this on UNIX programs can be found on [lolbas-project.github.io](https://lolbas-project.github.io).