---
authors: Ken
category: infra
---

# 🛠️ Unquoted path

Services and scheduled tasks can be vulnerable

## Theory

Unquoted Service Path vulnerability in Windows occurs when services are installed using paths containing spaces without proper quotation marks. If you obtain write permissions in the service's installation directory, you can execute malicious code with elevated privileges.


## Enumartion (PowerUp)

1. First Load the Tool

```
. .\PowerUp.ps1
```
2. Run

```
Invoke-AllChecks
```

## Exploitation

The `Invoke-AllChecks` command would provide you a command to abuse the vulnerable service. 
LogOff and LogIn to See effect. 


## Mitigation

To defend against Unquoted Service Path vulnerabilities, modify the service configuration to include proper quotation marks around the executable path. Moreover, review the permissions of service installation folder and binary file to prevent unauthorized changes.




