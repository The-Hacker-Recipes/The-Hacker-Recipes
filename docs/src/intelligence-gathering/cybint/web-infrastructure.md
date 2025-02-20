---
authors: Bnder1, ShutdownRepo
category: intelligence-gathering
---

# Web infrastructure

## Theory 

## Practice 

shodan : net:"SUBNET/MASK"
 - org:"company name"
   
zoomeye : IP/MASK

fofa.so

Get the DNS servers, their records, and map the domain:\
\-[https://dnsdumpster.com/](https://dnsdumpster.com/)\
IP enumeration + response header from domain name:\
\-[https://zoomeye.org](https://zoomeye.org)\
Find subdomains:\
\-[https://findsubdomains.com](https://findsubdomains.com)\
Find technologies used and versions of a webapp:\
\-[https://github.com/urbanadventurer/WhatWeb](https://github.com/urbanadventurer/WhatWeb)

Website caching platforms:\
\-[https://archive.org/](https://archive.org/)\
\-[https://archive.is/](https://archive.is/)

Google Analytics:

* The last piece of information that is really interesting is to check if the same Google Analytics / Adsense ID is used in several websites. This technique was discovered in 2015 and is well described here by [Bellingcat](https://www.bellingcat.com/resources/how-tos/2015/07/23/unveiling-hidden-connections-with-google-analytics-ids/).
* Certificates?









Using Google Dorks to find subdomains

```
# find subdomains
site:"something.com"

# without www and subd1
site:"something.com" -www -subd1
```