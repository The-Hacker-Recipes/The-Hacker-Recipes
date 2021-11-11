# Comments and metadata

## Theory

When requesting a web application, the server usually sends code \(in HTML, CSS, Javascript...\) in the response. This code is then rendered by the web browser. Web developers sometimes forget that this code is not protected, hence leaving sensitive comments in it.

Metadata can also be interesting when the target web apps use Content Management Systems \(CMS\) like WordPress or Drupal. Metadata can help identify the technologies and CMS used.

## Practice

Looking for comments and metadata can be done manually \(looking at the source codes\) or with tools like **Burp Suite** \(`Dashboard > New scan (Crawl)` then `Target > right click > Engagement tools > Find comments` \).

