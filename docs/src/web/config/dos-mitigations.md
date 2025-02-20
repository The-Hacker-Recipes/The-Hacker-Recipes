---
authors: ShutdownRepo
category: web
---

# 🛠️ Denial of Service (DoS)

## Theory

There are two distinct types of denial of service:

* Denial of Service (DoS): using a single machine, a DoS attack reduces or prevents accessibility of service for its users. It usually does so by flooding the targeted machine with a consequent amount of requests to overload the system or by exploiting logic flaws that make the target server compute way too much.
* Distributed Denial of Service (DDoS): a DDoS attack has the same goal as the DoS attack. Except it uses a multitude of compromised machines to cause a denial of service and usually relies on flooding rather than finding and exploiting logical flaws.

There are various ways to cause a denial of service by flooding such as:

* MAC flooding: flooding a switch with packets using different source MAC addresses.
* ARP poisoning/spoofing: linking multiple IP addresses with a single MAC address (to a target).
* Slow HTTP: sending HTTP requests in a slow and fragmented way, one at a time.
* File upload: exhausting the back-end system's disk space and network bandwidth by uploading lengthy files. Also, uploading a file that will be interpreted in the back-end could cause a DoS, if the file uploaded is malicious and its goal is to overload the system.
* ICMP flood: flooding the targeted machine with an overwhelming amount of ICMP requests.

The list is not exhaustive however, one can keep in mind that multiple categories exist, presenting a different approach for conducting a DoS attack: bandwidth, packets, TCP-related components, application layer, etc.

Testing for DoS in engagements can be useful for detecting applications and configurations vulnerabilities, by then providing the client with possible mitigation to prevent DoS attacks.

## Practice

### Websites

::: tabs

=== Stress testing

[hping3 ](https://github.com/antirez/hping)is a tool for firewall testing, OS fingerprinting, port scanning, etc. (see [manual](https://linux.die.net/man/8/hping3)).\
What's interesting is its DoS testing capabilities. [More examples on hping3.](https://linuxhint.com/hping3/)

The command sends a huge amount of packets with random source addresses to stress firewall state tables and other dynamic tables (IP based) within the TCP/IP stacks and firewall software.

```bash
hping3 --rand-source --flood $TARGET_IP
```

The command sends a huge amount of SYN packets with a specified port.

```bash
hping3 -S --flood -V -p $TARGET_PORT $TARGET_IP
```

Other specialized tools can be used such as [Hulk ](https://github.com/grafov/hulk)and [GoldenEye](https://github.com/jseidl/GoldenEye).

> [!CAUTION]
> [hping3](https://github.com/antirez/hping), [Hulk, ](https://github.com/grafov/hulk)and [GoldenEye ](https://github.com/jseidl/GoldenEye)should be used with care and in specific cases. \
> The number of requests they can send could crash the targeted system.


=== Directory fuzzing

Directory fuzzing is a key step during the reconnaissance phase. Depending on the number of threads used, a DoS could happen. Here's an example using [Feroxbuster](https://github.com/epi052/feroxbuster#threads-and-connection-limits-at-a-high-level).

```bash
feroxbuster -H "User-Agent: PENTEST" -w $WORDLIST -u $TARGET_IP -t $THREADS
```


=== File upload

Unrestricted file upload in a website can lead to DoS by uploading lengthy files.\
If the back-end server interprets any file uploaded (PHP, JSP...), a DoS could occur depending on the goal of the file's code.


=== Input length

By sending a very long password, a DoS attack can be possible. The password hashing implementation may exhaust its CPU and memory resources.

:::


## Resources

[https://www.netscout.com/what-is-ddos](https://www.netscout.com/what-is-ddos)

[https://ktflash.gitbooks.io/ceh_v9/content/91_dosddos_concepts.html](https://ktflash.gitbooks.io/ceh_v9/content/91_dosddos_concepts.html)

[https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html](https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html)

[https://www.vaadata.com/blog/dos-attack-testing-denial-of-service-pentest/](https://www.vaadata.com/blog/dos-attack-testing-denial-of-service-pentest/)

[https://www.acunetix.com/vulnerabilities/web/long-password-denial-of-service/](https://www.acunetix.com/vulnerabilities/web/long-password-denial-of-service/)