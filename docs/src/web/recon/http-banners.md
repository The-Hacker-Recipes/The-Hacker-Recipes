---
authors: ShutdownRepo
category: web
---

# HTTP response headers

## Theory

HTTP messages (requests and responses) always contain a line, header fields, an empty line and an optional message body. The header fields define the operating parameters of an HTTP transaction. Headers in request messages are called client headers while those in the responses are called server headers. On default web apps environments, it is not rare to find server headers that echo the technologies used like: `Server`, `X-Powered-By`, `X-AspNet-Version`...

HTTP headers can sometimes indicate the use of a [Content Management Systems (CMS)](cms.md) like WordPress or Drupal and help identify the technologies and CMS used.

## Practice

Send a simple HTTP request and in the response, look for server headers revealing the technologies and versions used.

```bash
curl --location --head $URL
```