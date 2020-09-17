# Directory fuzzing

## Theory

While Crawling allows testers to build the indexed architecture of website, this technique can't find directories and files that are not referenced. Directory fuzzing \(a.k.a. directory bruteforcing\) is a technique that can find some of those "hidden" paths. Dictionaries of common paths are used to request the web app for each path until exhaustion of the list.

## Practice

Tools like [dirb](http://dirb.sourceforge.net/) \(C\), [dirbuster](https://sourceforge.net/projects/dirbuster/) \(Java\), [gobuster](https://github.com/OJ/gobuster) \(Go\), [wfuzz](https://github.com/xmendez/wfuzz) \(Python\) and [ffuf](https://github.com/ffuf/ffuf) \(Go\) can do directory fuzzing/bruteforcing. Burp Suite can do it too. Depending on the web application, one will be better suited than another and additional options will be needed.

Directory fuzzing needs to be slowed down when testing production instances as it could lead to an unintended denial of service.

```bash
gobuster dir --useragent "PENTEST" -w /usr/share/seclists/Discovery/Web-Content/common.txt -u $URL
```

```bash
wfuzz --hc 404,403 -H "User-Agent: PENTEST" -c -z file,/usr/share/seclists/Discovery/Web-Content/common.txt $URL/FUZZ
```

```bash
ffuf -H "User-Agent: PENTEST" -c -w /usr/share/seclists/Discovery/Web-Content/common.txt -u $URL/FUZZ
```

In order to fuzz more accurately, there are many dictionaries adapted for many situations. The ultimate combo is [ffuf](https://github.com/SusmithKrishnan/torghost) + [fzf](https://github.com/junegunn/fzf) + [seclists](https://github.com/danielmiessler/SecLists).

