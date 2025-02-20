---
authors: 0xlildoudou
category: web
---

# API

## Theory

The API pentesting methodology begins with reconnaissance, where information is gathered about the API, including its endpoints, parameters, and authentication methods. Next, testers assess authentication and authorization to ensure proper access control and attempt to bypass them. Input validation is then tested by sending crafted payloads to identify vulnerabilities like injection attacks. Business logic testing follows, ensuring the API handles data and functions correctly without unintended consequences. Rate limiting and denial-of-service (DoS) protections are evaluated to prevent excessive requests. Finally, a detailed report is created, documenting findings, vulnerabilities, and recommendations for remediation.

## Practice 

### API types
* SOAP/XML Web Services : SOAP (Simple Object Access Protocol) is an XML-based protocol for exchanging structured information in the implementation of web services. 
* REST APIs (JSON) : The specificity of a REST API lies in its statelessness, use of standard HTTP methods (`GET`, `POST`, `PUT`, `DELETE`), and resource-based structure with responses typically formatted in JSON or XML.
* GraphQL : A query language for APIs offering a complete and understandable description of the data in your API.

### Endpoints discovering
Discover API endpoint with fuzzing.

::: tabs

=== FFUF

[FFUF](https://github.com/ffuf/ffuf) A fast web fuzzer written in Go.

```bash
ffuf -w /path/to/wordlist -u https://target/FUZZ
```

=== APIFuzzer

[APIFuzzer](https://github.com/KissPeter/APIFuzzer) reads your API description and step by step fuzzes the fields to validate if you application can cope with the fuzzed parameters.

```bash
APIFuzzer -s test/test_api/openapi_v2.json -u http://target:5000/ -r /tmp/reports/ --log debug 
```

=== Kiterunner

[kiterunner](https://github.com/assetnote/kiterunner) Excellent for discovering API endpoints. Use it to scan and brute force paths and parameters against target APIs.

```bash
kr scan https://domain.com/api/ -w routes-large.kite -x 20
kr scan https://domain.com/api/ -A=apiroutes-220828 -x 20
kr brute https://domain.com/api/ -A=raft-large-words -x 20 -d=0
kr brute https://domain.com/api/ -w /tmp/lang-english.txt -x 20 -d=0
```

:::

Wordlist for discover API endpoints

[chrislockard/api_wordlist](https://github.com/chrislockard/api_wordlist)

[yassineaboukir/List of API endpoints & objects](https://gist.github.com/yassineaboukir/8e12adefbd505ef704674ad6ad48743d)

### HTTP method

Identify HTTP Method used on the endpoints

::: tabs

=== HTTPMethods

[HTTPMethods](https://github.com/ShutdownRepo/httpmethods) this can be useful to look for HTTP verb tampering vulnerabilities and dangerous HTTP methods.

```bash
httpmethods -u http://www.example.com/
```

:::

### Parameter tampering

Experiment with adding or replacing parameters in requests to access unauthorized data or functionalities.

Example:
```
https://target.com/api/users/1 --> 401
https://target.com/api?users=1 --> 200
https://target.com/api/users?1 --> 200
```

### Version testing

Older API versions might be more susceptible to attacks. Always check for and test against multiple API versions.

Example:
```
https://target.com/api/v2/users/1 --> 401
https://target.com/api/v1/users/1 --> 200
```

## Resources

[hacktricks](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/web-api-pentesting)