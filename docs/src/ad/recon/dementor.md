---
authors: MatrixEditor
category: ad
---

# Dementor

In contrast to [Responder](https://github.com/lgandx/Responder), [*Dementor*](https://github.com/MatrixEditor/dementor)/[Docs](https://matrixeditor.github.io/dementor/) does not only offer traditional [LLMNR, NBTNS, MDNS poisoning](../movement/mitm-and-coerced-authentications/llmnr-nbtns-mdns-spoofing.md), it also provides an extensible architecture to expose rogue services.

* Near-complete protocol parity with responder plus several additional protocols (e.g. IPP, MySQL, X11, UPnP, …) (Compatibility matrix is here: [Docs - Compatibility](https://matrixeditor.github.io/dementor/compat.html))
* Two operation modes: *attack* and *analysis* similar to responder
* There is a fine-grained, per-protocol configuration available via a TOML configuration file. ([Docs - Configuration](https://matrixeditor.github.io/dementor/config/index.html))


## Basic operation modes

Dementor can be used to retrieve information from the local network passively as well as to capture credentials from clients.

::: tabs

=== UNIX-like

```bash
# Start in analysis mode (no answer poisoning)
Dementor -I $INTERFACE -A

# Start in attack mode (default mode)
Dementor --interface $INTERFACE

# Use custom configuration in new session
Dementor -c $CONFIG_PATH -I $INTERFACE

# Apply custom configuration and specify blacklist
Dementor -c $CONFIG_PATH -I $INTERFACE --ignore "$HOST"

# Specify configuration options on-the-fly (e.g. SMB off works
# well with relaying)
Dementor -I $INTERFACE -O SMB=Off
```

There is also support for the CUPS RCE (CVE-2024-47076 and CVE-2024-47175). More information in [Dementor Docs - Abusing CUPS for RCE](https://matrixeditor.github.io/dementor/examples/cups.html).

```bash
Dementor -I $INTERFACE -O IPP=On -O IPP.Port=$IPP_PORT \
    -O IPP.RemoteCmd="$IPP_CMD"
```

=== Windows

Not officially supported. Invocation is the same as on UNIX-like systems.

:::

## Logging

By default, logs are *disabled* and must be enabled explicitly either via CLI flags or in the TOML configuration ([Docs - Logging config](https://matrixeditor.github.io/dementor/config/logging.html))

```toml
[Log]
# enable creation of log files
Enabled = true
# the destination directory can be
#  - relative to the workspace dir
#  - relative to the current working dir (./ prefix)
#  - absolute (/ prefix)
LogDir = "logs"
```

Hashes can be captured as well as all passively identified hosts:
```toml
[Log.Stream.Hosts]
# Enable logging all identified clients within the network that
# either (1) establish a direct connection to dementor, or (2)
# via multicast/broadcast messages.
Path = "./client_hosts.txt"

[Log.Stream.Hashes]
# Saves captured hashes either to a single output file or into
# separate files.
Path = "./hash-collections"
# "Splits" the collected hashes into separate files.
Split = true
```