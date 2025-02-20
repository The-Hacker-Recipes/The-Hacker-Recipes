---
authors: ShutdownRepo
category: web
---

# MIME type sniffing

MIME type sniffing is an operation conducted by many browsers. Each browser behaves differently on that matter, but overall, MIME sniffing is an action where they determine a page content type depending on that page content. This is can be dangerous as it could allow attackers to hide HTML code into a `.jpg` file, and have the visitor's browser interpret the page and execute client code (XSS) because the browser determined the file was HTML code instead of a JPG image.

The XCTO ([`X-Content-Type-Options`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options)) security header can be used to indicate that the [MIME types](https://developer.mozilla.org/en-US/docs/Web/HTTP/Basics_of_HTTP/MIME_types) advertised in the [`Content-Type`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Type) headers should be followed and not be changed by the browser depending on the pages content. Websites that implement that security header with the `nosniff` directive must also include a valid `Content-Type` header in their responses.

## Resources

[https://www.keycdn.com/support/what-is-mime-sniffing](https://www.keycdn.com/support/what-is-mime-sniffing)

[https://www.denimgroup.com/resources/blog/2019/05/mime-sniffing-in-browsers-and-the-security-implications/](https://www.denimgroup.com/resources/blog/2019/05/mime-sniffing-in-browsers-and-the-security-implications/)

[https://blog.mozilla.org/security/2016/08/26/mitigating-mime-confusion-attacks-in-firefox/](https://blog.mozilla.org/security/2016/08/26/mitigating-mime-confusion-attacks-in-firefox/)

[https://mimesniff.spec.whatwg.org/](https://mimesniff.spec.whatwg.org/)