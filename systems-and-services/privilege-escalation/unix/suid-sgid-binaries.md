# SUID/SGID binaries

## Theory

On UNIX-like systems, binaries have permissions, just like any other file. Some of them often are over-privileged, sometimes allowing attackers to escalate privileges on the system. These permissions can be read, write, execute or extended ones like setuid, setgid, sticky mode, and so on.

The setuid/setgid \(SUID/SGID\) bit allows the binary to run with the privileges of the user/group owner instead of those of the user executing it. They can be spotted with the `s` or `S` permission in the file user or group owner permissions \(i.e. `---s--s---`\). When the file permissions features an uppercase `S` instead of a lowercase one, it means the corresponding user or group owner doesn't have execution rights.

{% hint style="warning" %}
**Limitations**

* Just like capabilities, setuid and setgid bits are unset when a file is copied with `cp`.
* Some partitions of the UNIX file system can be mounted with the `nosuid` option. In this case the setuid and setgid bits are ignored for binaries placed inside those partitions. It is a common good practice for tmpfs partitions like `/tmp` or`/run`. Searching the `/proc/mounts` pseudo-file for a `nosuid` flag can help find these partitions.
{% endhint %}

## Practice

All suid or sgid-enabled files the user can have access to can be listed with the following command.

```bash
find $starting_path -perm -u=s -type f 2>/dev/null
find $starting_path -perm -u=s -type f 2>/dev/null
```

Binaries with these permissions are then targets to exploit to obtain the user or group owner privileges. There are many techniques that attackers use to hijack those binaries and obtain those rights.

### Living of the land

Using standard binaries features to bypass security restrictions is called Living off the land.

{% page-ref page="living-off-the-land.md" %}

### Relative path calls

If a SUID/SGID binary makes calls to programs using relative paths instead of absolute paths, attackers can try to make the binary run a program of the attacker's choosing.

{% code title="vuln.c" %}
```c
int function(int argc, char *argv[]){
···
    system("ls") // instead of system("/usr/bin/cat")
···
}
```
{% endcode %}

In the example above, the SUID/SGID binary calls the `ls` program using a relative path. An attacker can try to create a `ls` program somewhere he has write access to and edit the `PATH` environment variable so that his custom program is executed when running the SUID/SGID binary.

```bash
PATH=.:$PATH ./vuln
```

### Binary exploitation

In some cases, the binary that have SUID/SGID permissions can be reverse-engineered and attackers find ways to change the execution flow of that program to make it run something else \(e.g. [buffer overflow](../../../binary-exploitation/buffer-overflow.md), [use-after-free](../../../binary-exploitation/use-after-free.md), ...\).

## References

{% embed url="https://www.hackingarticles.in/linux-privilege-escalation-using-suid-binaries/" caption="" %}

