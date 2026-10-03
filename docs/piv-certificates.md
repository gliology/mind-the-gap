# PIV certificate chain


The PIV backend issues a full X.509 chain rather than a set of self-signed certificates,
so that the card works with S/MIME, TLS client authentication, SSH and smartcard logon:

```
Root CA (self-signed, CA:TRUE)
└── (optional issuing CA, enabled with --intermediate)
    ├── 9A authentication   digitalSignature            clientAuth, msSmartcardLogon
    ├── 9C signature        digitalSignature, nonRepudiation   emailProtection
    ├── 9D key management   keyAgreement                emailProtection, clientAuth
    └── 9E card auth        digitalSignature            id-PIV-cardAuth
```

All keys are NIST P-256 and every certificate is signed with `ecdsa-with-SHA256`. Slot 9D
uses `keyAgreement` rather than `keyEncipherment` because these are ECDH keys and RFC 8813
forbids the latter on EC keys.

Slots 9A, 9C and 9D are bound to the cardholder; slot 9E is bound to the card and carries no
email address, as required by FIPS 201-3 section 4.2.3. Its subject uses a card identifier
derived from the seed rather than the card's serial number, so that `piv certify` (which runs
without any hardware) and `piv upload` produce identical certificates.

Export the root certificate with `mind-the-gap piv certify --kind root` and install it as a
trust anchor. The authorities are additionally written to the card's `msroots` object, where
the Windows minidriver picks them up.

Certificate generation is fully deterministic: signing uses RFC 6979 deterministic ECDSA
nonces, and the creation time defaults to the unix epoch, so re-running `piv certify` with
the same inputs reproduces the same bytes.
