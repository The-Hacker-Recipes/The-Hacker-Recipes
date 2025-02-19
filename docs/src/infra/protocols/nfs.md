---
authors: ShutdownRepo, 0xbugatti
---

# 🛠️ NFS

## Theory

NFS or Network File system allows a client to access files over a network in the same way they would access a local storage file.

A NFS server determines what ressources to make available and ensures to recognize validated clients. From the client perspective, the machine requests access to a share by issuing a mount request. If successful the client can view and interact with the share as if its his own disk.

This service is located on the port 2049.

## Practice
### Implement
```bash

echo '/mnt/sharedfolder 10.129.14.0/24(sync,no_subtree_check)' >> /etc/exports # editing NFS conf file
systemctl restart nfs-kernel-server # new configuration affect
exportfs

```
### Enumerate mountable directories.

To check which share is available for mount, _showmount_ can be used.

```
showmount -e  
/ * -> means that the root directory is shared to everyone on the network
/  -> means that the root directory is shared with

-o nolock -> (No Write Block) 
-o nfsvers=4 -> Important for NFS v4

```

### Mounting directories.

A local directory where the shared directory will be mounted is necessary.

```
mkdir /tmp/local_directory
mount -t nfs :/directory /tmp/infosec
```




### Exploiting NFS weak permissions

#### no_root_squash

Root squashing is a configuration that prevents remote root users to get a root access on the mounted NFS volume. Enabled by default remote root users are assigned as _nfsnobody ,_ which is a role that has the least local privileges.

Alternatively "no_root_squash" parameter turns off this configuration and gives to the remote user, root access to the NFS volume.

[https://book.hacktricks.xyz/linux-unix/privilege-escalation/nfs-no_root_squash-misconfiguration-pe](https://book.hacktricks.xyz/linux-unix/privilege-escalation/nfs-no_root_squash-misconfiguration-pe)

#### rw

Read and write permissions.

#### nohide
If another file system was mounted below an exported directory, this directory is exported by its own exports entry.

> [!TIP] TIP : within nmap scan use  --script=*nfs*
## Resources
