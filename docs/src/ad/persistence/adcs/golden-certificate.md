---
authors: ShutdownRepo
category: ad
---

# Golden certificate

## Theory

Golden certificates usually refer to one of two types of attacks.

* Forge certificate and sign them with the CA cert private key --> [#stolen-ca](certificate-authority.md#stolen-ca)
* Modify a template and turn it into a SmartCard template --> [access-controls.md](access-controls.md)

Most tools ([certsync](https://github.com/zblurx/certsync), [certipy](https://github.com/ly4k/Certipy#golden-certificates)) and resources refer to the [#stolen-ca](certificate-authority.md#stolen-ca) technique when mentioning Golden Certificates. Since Golden Tickets consist in Kerberos tickets forged when knowing the KRBTGT keys, it makes sense to call "Golden Certificate" a technique that consists in forging a certificate when knowing the CA private key.

## Resources

[https://cyberstoph.org/posts/2019/12/an-introduction-to-golden-certificates/](https://cyberstoph.org/posts/2019/12/an-introduction-to-golden-certificates/)

[https://www.hackingarticles.in/domain-persistence-golden-certificate-attack/](https://www.hackingarticles.in/domain-persistence-golden-certificate-attack/)

[https://san3ncrypt3d.com/2022/02/19/gc/](https://san3ncrypt3d.com/2022/02/19/gc/)

> [!YOUTUBE] https://www.youtube.com/watch?v=2KZCsfplSlI