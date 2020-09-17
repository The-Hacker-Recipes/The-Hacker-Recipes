# 🛠️ NFS

## Theory

NFS or Network File system allows a client to access files over a network in the same way they would access a local storage file.

A NFS server determines what ressources to make available and ensures to recognize validated clients. From the client perspective, the machine requests access to a share by issuing a mount request. If successful the client can view and interact with the share as if its his own disk.

This service is located on the port 2049.

## Practice

### Enumerate mountable directories.

To check which share is available for mount, _showmount_ can be used.

```text
showmount -e <TARGET_IP> 
/ *    -> means that the root directory is shared to everyone on the network
/ <IP> -> means that the root directory is shared with <IP>
```

### Mounting directories.

A local directory where the shared directory will be mounted is necessary.

```text
mkdir /tmp/local_directory
mount -t nfs <IP>:/directory /tmp/infosec
```

### Exploiting NFS weak permissions

#### no\_root\_squash

Root squashing is a configuration that prevents remote root users to get a root access on the mounted NFS volume. Enabled by default remote root users are assigned as _nfsnobody ,_ which is a role that has the least local privileges.

Alternatively "no\_root\_squash" parameter turns off this configuration and gives to the remote user, root access to the NFS volume.

{% embed url="https://book.hacktricks.xyz/linux-unix/privilege-escalation/nfs-no\_root\_squash-misconfiguration-pe" caption="" %}

## References

