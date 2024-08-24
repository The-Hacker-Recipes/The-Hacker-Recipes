# Golden certificate

## Theory

Golden certificates usually refer to one of two types of attacks.

* Forge certificate and sign them with the CA cert private key --> [#stolen-ca](certificate-authority.md#stolen-ca "mention")
* Modify a template and turn it into a SmartCard template --> [access-controls.md](access-controls.md "mention")

Most tools ([certsync](https://github.com/zblurx/certsync), [certipy](https://github.com/ly4k/Certipy#golden-certificates)) and resources refer to the [#stolen-ca](certificate-authority.md#stolen-ca "mention") technique when mentioning Golden Certificates. Since Golden Tickets consist in Kerberos tickets forged when knowing the KRBTGT keys, it makes sense to call "Golden Certificate" a technique that consists in forging a certificate when knowing the CA private key.

## Resources

{% embed url="https://cyberstoph.org/posts/2019/12/an-introduction-to-golden-certificates/" %}

{% embed url="https://www.hackingarticles.in/domain-persistence-golden-certificate-attack/" %}

{% embed url="https://san3ncrypt3d.com/2022/02/19/gc/" %}

{% embed url="https://www.youtube.com/watch?v=2KZCsfplSlI" %}
