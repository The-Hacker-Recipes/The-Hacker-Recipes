# Directory fuzzing

## Theory

While Crawling allows testers to build the indexed architecture of website, this technique can't find directories and files that are not referenced. Directory fuzzing (a.k.a. directory bruteforcing) is a technique that can find some of those "hidden" paths. Dictionaries of common paths are used to request the web app for each path until exhaustion of the list. This technique relies on the attacker using a dictionnary/wordlist. A request is made for every line of the wordlist to differentiate pages that exist and pages that don't

## Practice

Tools like [dirb](http://dirb.sourceforge.net) (C), [dirbuster](https://sourceforge.net/projects/dirbuster/) (Java), [gobuster](https://github.com/OJ/gobuster) (Go), [wfuzz](https://github.com/xmendez/wfuzz) (Python) and [ffuf](https://github.com/ffuf/ffuf) (Go) can do directory fuzzing/bruteforcing. Burp Suite can do it too. Depending on the web application, one will be better suited than another and additional options will be needed.

Directory fuzzing needs to be slowed down when testing production instances as it could lead to an unintended denial of service.

```bash
gobuster dir --useragent "PENTEST" -w "/path/to/wordlist.txt" -u $URL
```

```bash
wfuzz --hc 404,403 -H "User-Agent: PENTEST" -c -z file,"/path/to/wordlist.txt" $URL/FUZZ
```

```bash
ffuf -H "User-Agent: PENTEST" -c -w "/path/to/wordlist.txt" -u $URL/FUZZ
```

Another great tool named [feroxbuster](https://github.com/epi052/feroxbuster) (Rust) can do really fast recursive content discovery. The tools mentioned above don't recurse in found directories.

```bash
feroxbuster -H "User-Agent: PENTEST" -w "/path/to/wordlist.txt" -u http://192.168.10.10/
```

In order to fuzz more accurately, there are many dictionaries adapted for many situations, most of which can be downloaded from SecLists. SecLists can be installed (`apt install seclists` or downloaded directly from [the GitHub repo](https://github.com/danielmiessler/SecLists)).

The ultimate combo is [ffuf](https://github.com/ffuf/ffuf) + [fzf](https://github.com/junegunn/fzf) + [seclists](https://github.com/danielmiessler/SecLists).

{% hint style="success" %}
In the following command, [fzf](https://github.com/junegunn/fzf) is used to print a file fuzzer prompt allowing the user to quickly choose the perfect wordlist for content discovery.

```bash
feroxbuster -H "User-Agent: PENTEST" -w `fzf-wordlists` -u http://192.168.10.10/
```

In this case, `fzf-wordlists` is an alias to the following command using fzf and find to fuzz wordlists from specific directories.

```bash
find /usr/share/seclists /usr/share/wordlists /usr/share/dirbuster /usr/share/wfuzz /usr/share/dirb -type f | fzf
```
{% endhint %}
