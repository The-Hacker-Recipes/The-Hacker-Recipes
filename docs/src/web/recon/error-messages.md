---
authors: ShutdownRepo
category: web
---

# Error messages

## Theory

It is common to browse websites that leak information regarding the technologies they use in various error messages. Attackers can try to willfully raise errors to find those information and have a better understanding of the attack surface.

## Practice

Raising error pages and messages can be done manually when browsing the website by doing the following actions

* requesting a page that doesn't exist (status code 404)
* requesting a page without the proper rights (access control raising status code 403)
* supplying garbage (special chars or wrong syntax) in user inputs (parameters, forms, headers) to raise syntax of filter errors.