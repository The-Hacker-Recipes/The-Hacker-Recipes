---
authors: junron, ShutdownRepo
category: contributing
---

# Variables

Throughout The Hacker Recipes, we use variables to make commands and code samples more adaptable to your specific environment.
Click on any variable (prefixed with `$`) to modify its value, and that change will be reflected across the entire site.
This page is made to centralize major variables and set them once to have them reflected everywhere else.

> [!SUCCESS]
> Variables are stored in your browser's local storage, and will persist for 24 hours. This means that 24 hours after setting them, they should be removed. This is to avoid having you leaking credentials by accident. And rest assured, nothing is sent to us.

## Exegol history import

[Exegol history](https://github.com/ThePorgs/Exegol-history) is a feature of the [Exegol](https://github.com/ThePorgs/Exegol) ecosystem (professional offensive security environments) that helps Exegol users manage their credentials locally during an engagement, and use those credentials dynamically with the pre-set and variable history.

The component below allows importing commands from an Exegol history buffer. When pasted, any variables in the commands will be automatically detected and will be applied in The Hacker Recipes. Commented line will be ignored.

<ExegolHistoryImport />


## Standard Variables

These are the standard variables used throughout the documentation:

```bash
# Domain/Network Variables
$DOMAIN       # Domain name (e.g., "CONTOSO.LOCAL")
$DOMAIN_SID   # Domain SID (e.g., "S-1-5-21-1234567890-1234567890-1234567890")
$DC_HOST      # Domain Controller hostname (e.g., "DC01")
$DC_IP        # Domain Controller IP address (e.g., "192.168.1.10")
$TARGET       # Target machine IP (non-DC) (e.g., "192.168.1.50")

# User/Authentication Variables
$USER         # Username (e.g., "jdoe")
$PASSWORD     # User password (e.g., "Password123!")
$NT_HASH      # NT hash (e.g., "64F12CDDAA88057E06A81B54E73B949B")
$LM_HASH      # LM hash (e.g., "98A1092DEADBEEF7C3D77C3D77C3D77C")

# Attacker Variables
$ATTACKER_IP  # Your machine's IP address (e.g., "192.168.1.100")
$INTERFACE    # Network interface (e.g., "eth0" or "tun0")
```

## Resetting variables

All saved variables automatically expire after 24 hours. If you need to reset them before that, you can clear your browser's local storage for this website.