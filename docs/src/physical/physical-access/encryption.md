---
authors: ShutdownRepo
category: physical
---

# Encryption

### Bitpixie

To bypass BitLocker, a proof-of-concept can be used called 'bitpixie': [https://github.com/andigandhi/bitpixie](https://github.com/andigandhi/bitpixie).
The requirements for this attack are:
- It must use BitLocker without pre-boot authentication.
- It must be able to boot in PXE mode. Ideally, the PXE boot option is not disabled in the bios. On some systems, this attack may work even if PXE boot is disabled, as PXE boot can be enabled by connecting an external network card.
- The PCR Validation must not include 4. Check with `manage-bde -protectors -get c:` This is default behaviour.
