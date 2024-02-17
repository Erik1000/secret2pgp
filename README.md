# Secret2PGP

Derive an OpenPGP certificate with signing (S), authentication (A) and encryption (E) subkeys from a 256bit secret.

## Installation

```
$ cargo install --git https://github.com/Erik1000/secret2pgp.git
```

## Goal

The goal was to abuse an [ISO-14443A] NFC tag to store a cryptographic key and an identifier which can be used to authenticate the tag via a web request.

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

## Implementation

* Use a cryptographically secure pseudorandom number generator to generate two independent 256bit sequences. Call the first `identity_key` and the second `secret_key`.
* Hash the `identity_key` using `SHA256(identity_key)` (no salt). The output is the `identity_hash`.
* Run `HKDF-Extract` with the `secret_key` as `input key material` (IKM), use no salt. The output is the `pseudorandom key` (PRK).
* Define a collision-resistant bit sequence for domain separation (This implementation uses `tag.erik-tesar.com`).
* Generate the cryptographic keys using `HKDF-Expand` with the following `info` fields and each with an output length of 256bit.
  * `DOMAIN_SEPARATION/tag/openpgp/primary-key` as `primary_key`
  * `DOMAIN_SEPARATION/tag/openpgp/subkey/sig/0` as `signing_subkey`
  * `DOMAIN_SEPARATION/tag/openpgp/subkey/aut/0` as `authentication_subkey`
  * `DOMAIN_SEPARATION/tag/openpgp/subkey/enc/0` as `encryption_subkey`
* Use the output to build 3 `Ed25519` keys and one `X25519` key.
* Define a point in time as `creation_time` for this tag identity.
* Build the OpenPGP certificate using `creation_time` as time for the key and signature creation time:
  * `primary_key` is the primary key.
  * `signing_subkey` is a signing subkey.
  * `authentication_subkey` is an authentication subkey.
  * `encryption_subkey` is a transport and storage encryption subkey.
  * Do not forget the binding signatures for the primary and the subkeys.
  * Use the raw (not the hex encoded!) value of the Tag UID to add an OpenPGP UserID to the OpenPGP certificate:
    * encode the UID byte sequence using `Base64UrlsafeNoPad(uid)`.
    * to the output append `@DOMAIN_SEPARATION`. The output will be the primary UserID for this OpenPGP certificate.
    * Add the binding signature from the primary key for this UserID
* Use the signing subkey of the OpenPGP certificate to create a signature over the serialized form of the tag identity to bind the tag uid and `identity_hash` to this OpenPGP certificate.
* Store the OpenPGP public certificate as well as the tag uid and the `identity_hash` on the server.
* Store a link containing the `identity_key` as query and the `secret_key` as the frament identifier of the URL (after `#`).

An example URL generated using `secret2pgp generate 0489945AE17180` would be:
`https://tag.erik-tesar.com/v1/t/open?i=8IvJg0bkZQedYxbb-UjOSNLyZXxTQFuxg73k2DlsMrw#s=e1u4T7Hnarzhj3gXIf6o8ceqCdiBCO1ZcouRQb1a_7M`

With the following (prettified) JSON document to store on the server:
```json
{
  "identity": {
    "uid": "BImUWuFxgA",
    "creation_time": "2024-02-17T11:34:45.897898929+00:00",
    "identity_hash": "N4vG14l0kT_820BMXnO2FTkI2ib0qSiNjUxK6PCu-Gk",
    "pgp_fingerprint": "70C6D60D406BB1263523A51C637E4AE9FBE8DFB7"
  },
  "pgp_certificate": "xjMEZdCZ1RYJKwYBBAHaRw8BAQdAAtnHDiVjmszEj_vdRe32zCjox7OUGWGJHw1L3UNZkjnCwAsEHxYKAH0FgmXQmdUDCwkHCRBjfkrp--jft0cUAAAAAAAeACBzYWx0QG5vdGF0aW9ucy5zZXF1b2lhLXBncC5vcmcyKZdA2vKxsG55wp4K0C6yhJJoWLwpJ3wj_B-BTUpupwMVCggCmwECHgEWIQRwxtYNQGuxJjUjpRxjfkrp--jftwAA9g0BAOoLeceFZKdKCWIQwNy9og_icVuRE-yH2H_aTFjyJ3YEAQCNa4lbfjVFCK-a-z-AmgjG61rt7txp-aZDjkhKAc34Ds0fPEJJbVVXdUZ4Z0FAdGFnLmVyaWstdGVzYXIuY29tPsLADgQTFgoAgAWCZdCZ1QMLCQcJEGN-Sun76N-3RxQAAAAAAB4AIHNhbHRAbm90YXRpb25zLnNlcXVvaWEtcGdwLm9yZ66FseAfQ9C_B6NciMbtx89yH4bd5biwnpkgfU1VR6zXAxUKCAKZAQKbAQIeARYhBHDG1g1Aa7EmNSOlHGN-Sun76N-3AABaQQEAuKDVLX11RadNP6LzGw43KWPoLDkNYm7VKU_b-McqskcA_210nrd5T9Xua_5GKlALXqv6UbYKwEYUOYWAelO-rzgFzjMEZdCZ1RYJKwYBBAHaRw8BAQdAAU9ZS040-I2piOzrzA3UhV1Sc3hnGq5eJr09mHMS2_XCwL8EGBYKATEFgmXQmdUJEGN-Sun76N-3RxQAAAAAAB4AIHNhbHRAbm90YXRpb25zLnNlcXVvaWEtcGdwLm9yZ2m1Kd8_B8wdz9bx_VdVnJKb-HqXGuAtJT8F4f0xZzAnApsCvqAEGRYKAG8FgmXQmdUJEIggW_gOIHHCRxQAAAAAAB4AIHNhbHRAbm90YXRpb25zLnNlcXVvaWEtcGdwLm9yZySqxF_Jix4WIPU4VCz912YO5G1IqSXzMfg6y_nVvPZsFiEEPLokPcNiW9BoAhGUiCBb-A4gccIAAB38AQCKG6SrZsfA1qQrJJcZs_0_KmyLGsI_9WNKXWtfyI4f0wD-PwKWihzpe6vRtbb8QTRkKy5MuyTHK991RG5QNWh2fwQWIQRwxtYNQGuxJjUjpRxjfkrp--jftwAAupUBAM6C7DbPpxbjEB0eUUd4vbHQ9NsCX_jcQJdU9X_Zem6yAP9vJcRyl1ARS0sCPKzqp2hnwm04NNu3U5dQ3ymvVtZyAs4zBGXQmdUWCSsGAQQB2kcPAQEHQJU3U56nXvmcBNvqo0T5AHWCIXln5yx3ObtfKgTpK9anwsC_BBgWCgExBYJl0JnVCRBjfkrp--jft0cUAAAAAAAeACBzYWx0QG5vdGF0aW9ucy5zZXF1b2lhLXBncC5vcmfar6j5uX3ojE-op2yW70QwCdq4IH5YTIwuGFqXYOzfmwKbIL6gBBkWCgBvBYJl0JnVCRDfDbHr01tJwUcUAAAAAAAeACBzYWx0QG5vdGF0aW9ucy5zZXF1b2lhLXBncC5vcmdS7narQ5IjIBmtDPQBnUaT9BsC4ZGclt2ifxSTKTkbJxYhBOv1D2G0tHbrniVvJ98NsevTW0nBAABDOAD_achSJCGa45Ls_3-ryJ_tgD1Nr-Z9z6ilJd10xbYKwzUA_3HdmH6QfdPevfhJM71_3zODPgsPTQxbE0vL6ShfFJcMFiEEcMbWDUBrsSY1I6UcY35K6fvo37cAAMmmAP9aC-Kz-Z4KAWQkhI92E4bYwPCOdpFv_dgkUxqJAkljWQD9Grs1f-iZUhgvHdZ1AGL9IokfsaSyVmz37k3r31q1Qg3OOARl0JnVEgorBgEEAZdVAQUBAQdAnx5VOOLeFSuJp-aJOX4lTHwo94SXXT4-sXkNn2uiX14DAQgHwsAABBgWCgByBYJl0JnVCRBjfkrp--jft0cUAAAAAAAeACBzYWx0QG5vdGF0aW9ucy5zZXF1b2lhLXBncC5vcmdXEbULJYJ65ecqfGOR33mE6lAvenuTshyGIniDtlnBqgKbDBYhBHDG1g1Aa7EmNSOlHGN-Sun76N-3AABqtgD_ct8JHv9F_tt4tfMJzMmxx9anV5s-jrdxLeWF34MTFxQA_RiY91mL5mlCvZm67JgN9mDIeSt3ZPwR4MUnoJiov2IB",
  "pgp_identity_self_signature": "xA0DAAgWiCBb-A4gccIBy8ALYgAAAAAAeyJ1aWQiOiJCSW1VV3VGeGdBIiwiY3JlYXRpb25fdGltZSI6IjIwMjQtMDItMTdUMTE6MzQ6NDUuODk3ODk4OTI5KzAwOjAwIiwiaWRlbnRpdHlfaGFzaCI6Ik40dkcxNGwwa1RfODIwQk1Ybk8yRlRrSTJpYjBxU2lOalV4SzZQQ3UtR2siLCJwZ3BfZmluZ2VycHJpbnQiOiI3MEM2RDYwRDQwNkJCMTI2MzUyM0E1MUM2MzdFNEFFOUZCRThERkI3In3CvQQAFggAbwWCZdCZ1QkQiCBb-A4gccJHFAAAAAAAHgAgc2FsdEBub3RhdGlvbnMuc2VxdW9pYS1wZ3Aub3JnUdz6ZXSiMA1uM6cK6zMW_aQG7arJO-Fu9Pdavcxr1eEWIQQ8uiQ9w2Jb0GgCEZSIIFv4DiBxwgAAgy4BANxSr9KwoBiavN9y7ougpOem85Zwj3zsH4SWZhsCXP9SAQDh0hwZqQEpHS5wSSjmrzH5ITxUM6p2bNa-64wHbcUGAQ"
}
```

And the output of `secret2pgp inspect tag.json`:
```
Uid:
0489945ae17180
Created:
2024-02-17 11:34:45.897898929 UTC
IdentityHash:
378bc6d78974913ffcdb404c5e73b6153908da26f4a9288d8d4c4ae8f0aef869
Fingerprint:
70C6D60D406BB1263523A51C637E4AE9FBE8DFB7
Certificate:
-----BEGIN PGP PUBLIC KEY BLOCK-----
Comment: 70C6 D60D 406B B126 3523  A51C 637E 4AE9 FBE8 DFB7
Comment: <BImUWuFxgA@tag.erik-tesar.com>

xjMEZdCZ1RYJKwYBBAHaRw8BAQdAAtnHDiVjmszEj/vdRe32zCjox7OUGWGJHw1L
3UNZkjnCwAsEHxYKAH0FgmXQmdUDCwkHCRBjfkrp++jft0cUAAAAAAAeACBzYWx0
QG5vdGF0aW9ucy5zZXF1b2lhLXBncC5vcmcyKZdA2vKxsG55wp4K0C6yhJJoWLwp
J3wj/B+BTUpupwMVCggCmwECHgEWIQRwxtYNQGuxJjUjpRxjfkrp++jftwAA9g0B
AOoLeceFZKdKCWIQwNy9og/icVuRE+yH2H/aTFjyJ3YEAQCNa4lbfjVFCK+a+z+A
mgjG61rt7txp+aZDjkhKAc34Ds0fPEJJbVVXdUZ4Z0FAdGFnLmVyaWstdGVzYXIu
Y29tPsLADgQTFgoAgAWCZdCZ1QMLCQcJEGN+Sun76N+3RxQAAAAAAB4AIHNhbHRA
bm90YXRpb25zLnNlcXVvaWEtcGdwLm9yZ66FseAfQ9C/B6NciMbtx89yH4bd5biw
npkgfU1VR6zXAxUKCAKZAQKbAQIeARYhBHDG1g1Aa7EmNSOlHGN+Sun76N+3AABa
QQEAuKDVLX11RadNP6LzGw43KWPoLDkNYm7VKU/b+McqskcA/210nrd5T9Xua/5G
KlALXqv6UbYKwEYUOYWAelO+rzgFzjMEZdCZ1RYJKwYBBAHaRw8BAQdAAU9ZS040
+I2piOzrzA3UhV1Sc3hnGq5eJr09mHMS2/XCwL8EGBYKATEFgmXQmdUJEGN+Sun7
6N+3RxQAAAAAAB4AIHNhbHRAbm90YXRpb25zLnNlcXVvaWEtcGdwLm9yZ2m1Kd8/
B8wdz9bx/VdVnJKb+HqXGuAtJT8F4f0xZzAnApsCvqAEGRYKAG8FgmXQmdUJEIgg
W/gOIHHCRxQAAAAAAB4AIHNhbHRAbm90YXRpb25zLnNlcXVvaWEtcGdwLm9yZySq
xF/Jix4WIPU4VCz912YO5G1IqSXzMfg6y/nVvPZsFiEEPLokPcNiW9BoAhGUiCBb
+A4gccIAAB38AQCKG6SrZsfA1qQrJJcZs/0/KmyLGsI/9WNKXWtfyI4f0wD+PwKW
ihzpe6vRtbb8QTRkKy5MuyTHK991RG5QNWh2fwQWIQRwxtYNQGuxJjUjpRxjfkrp
++jftwAAupUBAM6C7DbPpxbjEB0eUUd4vbHQ9NsCX/jcQJdU9X/Zem6yAP9vJcRy
l1ARS0sCPKzqp2hnwm04NNu3U5dQ3ymvVtZyAs4zBGXQmdUWCSsGAQQB2kcPAQEH
QJU3U56nXvmcBNvqo0T5AHWCIXln5yx3ObtfKgTpK9anwsC/BBgWCgExBYJl0JnV
CRBjfkrp++jft0cUAAAAAAAeACBzYWx0QG5vdGF0aW9ucy5zZXF1b2lhLXBncC5v
cmfar6j5uX3ojE+op2yW70QwCdq4IH5YTIwuGFqXYOzfmwKbIL6gBBkWCgBvBYJl
0JnVCRDfDbHr01tJwUcUAAAAAAAeACBzYWx0QG5vdGF0aW9ucy5zZXF1b2lhLXBn
cC5vcmdS7narQ5IjIBmtDPQBnUaT9BsC4ZGclt2ifxSTKTkbJxYhBOv1D2G0tHbr
niVvJ98NsevTW0nBAABDOAD/achSJCGa45Ls/3+ryJ/tgD1Nr+Z9z6ilJd10xbYK
wzUA/3HdmH6QfdPevfhJM71/3zODPgsPTQxbE0vL6ShfFJcMFiEEcMbWDUBrsSY1
I6UcY35K6fvo37cAAMmmAP9aC+Kz+Z4KAWQkhI92E4bYwPCOdpFv/dgkUxqJAklj
WQD9Grs1f+iZUhgvHdZ1AGL9IokfsaSyVmz37k3r31q1Qg3OOARl0JnVEgorBgEE
AZdVAQUBAQdAnx5VOOLeFSuJp+aJOX4lTHwo94SXXT4+sXkNn2uiX14DAQgHwsAA
BBgWCgByBYJl0JnVCRBjfkrp++jft0cUAAAAAAAeACBzYWx0QG5vdGF0aW9ucy5z
ZXF1b2lhLXBncC5vcmdXEbULJYJ65ecqfGOR33mE6lAvenuTshyGIniDtlnBqgKb
DBYhBHDG1g1Aa7EmNSOlHGN+Sun76N+3AABqtgD/ct8JHv9F/tt4tfMJzMmxx9an
V5s+jrdxLeWF34MTFxQA/RiY91mL5mlCvZm67JgN9mDIeSt3ZPwR4MUnoJiov2IB
=1uOg
-----END PGP PUBLIC KEY BLOCK-----

Signature:
-----BEGIN PGP SIGNATURE-----

xA0DAAgWiCBb+A4gccIBy8ALYgAAAAAAeyJ1aWQiOiJCSW1VV3VGeGdBIiwiY3Jl
YXRpb25fdGltZSI6IjIwMjQtMDItMTdUMTE6MzQ6NDUuODk3ODk4OTI5KzAwOjAw
IiwiaWRlbnRpdHlfaGFzaCI6Ik40dkcxNGwwa1RfODIwQk1Ybk8yRlRrSTJpYjBx
U2lOalV4SzZQQ3UtR2siLCJwZ3BfZmluZ2VycHJpbnQiOiI3MEM2RDYwRDQwNkJC
MTI2MzUyM0E1MUM2MzdFNEFFOUZCRThERkI3In3CvQQAFggAbwWCZdCZ1QkQiCBb
+A4gccJHFAAAAAAAHgAgc2FsdEBub3RhdGlvbnMuc2VxdW9pYS1wZ3Aub3JnUdz6
ZXSiMA1uM6cK6zMW/aQG7arJO+Fu9Pdavcxr1eEWIQQ8uiQ9w2Jb0GgCEZSIIFv4
DiBxwgAAgy4BANxSr9KwoBiavN9y7ougpOem85Zwj3zsH4SWZhsCXP9SAQDh0hwZ
qQEpHS5wSSjmrzH5ITxUM6p2bNa+64wHbcUGAQ==
=Q+9a
-----END PGP SIGNATURE-----
```

## Other

Uses [`sequoia-openpgp`] (with rust crypto backend) for OpenPGP and the [RustCrypto] crates for hashing etc.

This is a CLI but can be easily split into a library which would compile to WASM.

[ISO-14443A]: <https://nfc-tools.github.io/resources/standards/iso14443A/>
[NDEF]: <https://learn.adafruit.com/adafruit-pn532-rfid-nfc/ndef>
[`sequoia-openpgp`]: <https://sequoia-pgp.org/>
[RustCrypto]: <https://github.com/rustcrypto/https://github.com/rustcrypto/>