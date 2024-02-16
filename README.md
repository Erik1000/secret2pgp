# Secret2PGP

Derive an OpenPGP certificate with signing (S), authentication (A) and encryption (E) subkeys from a 256bit secret.

## Goal

The goal was to abuse an ISO-14443A NFC tag to store a cryptographic key and an identifier which can be used to authenticate the tag via a web request.

## Idea

Store a [NDEF] record containing an URL to a known website. In the URL, store two "secrets": 

* one that server recieves and that acts as a password (the `identity_key`)
* and one that will not be sent to the server but can be accessed by the client/browser (the `secret_key`).

The latter is achieved by using the hash (`#`) in the URL at the end, since everything after the hash will not be sent to the server.

Obviously, the server could load malicious javascript to steal the `secret_key`, but this is a fun project which does not include this attack vector.

The server stores non-sensitive information:
* the sha256 hash of the `identity_key` in order to authenticate the nfc tag
* the public keys of the derived OpenPGP certificate

The important part is that every NFC capable smartphone can scan the tag and from there, you can implement everything in an App or even more accessible in an WebApp that gets loaded from the stored URL.

One easy example which only uses the `identity_key` to authenticate the tag is to redirect the client to a unlisted youtube video.

One more advanced example would be to encrypt a document (e.g. tickets to a concert) with the derived public key and provide a friend with a device that scans the nfc tag, derives the openpgp private key and then decrypts it.

# Installation

```
$ cargo install --git https://github.com/Erik1000/secret2pgp.git
```

# Other

Uses [`sequoia-openpgp`] (with rust crypto backend) for OpenPGP and the [RustCrypto] crates for hashing etc.

This is a CLI but can be easily split into a library which would compile to WASM.

[ISO-14443A]: <https://nfc-tools.github.io/resources/standards/iso14443A/>
[NDEF]: <https://learn.adafruit.com/adafruit-pn532-rfid-nfc/ndef>
[`sequoia-openpgp`]: <https://sequoia-pgp.org/>
[RustCrypto]: <https://github.com/rustcrypto/https://github.com/rustcrypto/>