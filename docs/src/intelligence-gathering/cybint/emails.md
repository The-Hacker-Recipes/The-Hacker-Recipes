---
authors: ShutdownRepo
category: intelligence-gathering
---

# Emails

## Theory 

Searching for emails is a common part of an external pentest and could also be useful for internal pentest, depending on the perimeter and Red Team. 
Find emails could help to get more information about the target's mail servers. 
If a user's emails credentials have been compromised it could help to find others credentials for this user or to use Social Engineering attacks, such as phishing.

## Workflow 

Here is a workflow divided in 3 parts, the first part is about finding emails, the second one to know if the email leaked in a data breach and the third one to find the data breach. 
This workflow is still in process and is not exhaustive.

## Practice 

EMAIL SEARCH/VALIDATION 
Search for email address on a website: 
-[http://www.email-search.org/search-emails](http://www.email-search.org/search-emails/) (Free) 
Search for email addresses with a domain name: 
-[https://hunter.io](https://hunter.io/) (Half free) 
Get the target's email format with domain name: 
-[https://www.email-format.com](https://www.email-format.com/) (Free) 
Making email list with a domain by permuting name and surname: -[http://metricsparrow.com/toolkit/email-permutator](http://metricsparrow.com/toolkit/email-permutator/) (Free) 
Verify if an email address exists: 
-[https://verifalia.com/validate-email](https://verifalia.com/validate-email) (Free) 
Verify email validity, check SMTP servers: 
[-https://dnslytics.com/email-test](https://dnslytics.com/email-test) (Free)

EMAIL/PASSWORD LEAKS 
Verify if the email has been compromised in data breach: -[https://haveibeenpwned.com](https://haveibeenpwned.com/) (Free) 
-[https://ghostproject.fr](https://ghostproject.fr) (Half free) 
-[https://www.dehashed.com](https://www.dehashed.com/) (Half free) 
-[https://github.com/khast3x/h8mail](https://github.com/khast3x/h8mail) (Could need non-free API's keys) 
Find the leaked database: 
-[https://www.snusbase.com](https://www.snusbase.com/) (Non-free) 
-[https://www.dehashed.com](https://www.dehashed.com/) (Non-free) 
Deepweb search engines: 
-Notevil ([http://hss3uro2hsxfogfq.onion/index.php](http://hss3uro2hsxfogfq.onion/index.php)) 
-Candle ([http://gjobqjj7wyczbqie.onion](http://gjobqjj7wyczbqie.onion)) 
-Ahmia ([http://msydqstlz2kzerdg.onion/](http://msydqstlz2kzerdg.onion/))