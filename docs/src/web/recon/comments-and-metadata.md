---
authors: ShutdownRepo
category: web
---

# Comments and metadata

## Theory

When requesting a web application, the server usually sends code (in HTML, CSS, Javascript...) in the response. This code is then rendered by the web browser. Web developers sometimes forget that this code is not protected, hence leaving sensitive comments in it.

Metadata can sometimes indicate the use of a [Content Management Systems (CMS)](cms.md) like WordPress or Drupal and help identify the technologies and CMS used.

## Practice

Looking for comments and metadata can be done manually (looking at the source codes) or with tools like Burp Suite (`Dashboard > New scan (Crawl)` then `Target > right click > Engagement tools > Find comments` ).