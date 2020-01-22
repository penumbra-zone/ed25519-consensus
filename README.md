Zcash-flavored Ed25519 for use in [Zebra][zebra].

Zcash uses Ed25519 for [JoinSplit signatures][zcash_protocol_jssig] with
particular consensus-critical validation rules.  These rules are not part of
the Ed25519 specification in [RFC8032], which does not specify the set of valid
Ed25519 signatures and does not require conformant implementations to agree on
whether a signature is valid.  Because the Zcash-flavored validation rules are
consensus-critical, Zebra requires an Ed25519 library that implements the
Zcash-flavored validation rules specifically, which this crate provides.

[zcash_protocol_jssig]: https://zips.z.cash/protocol/protocol.pdf#concretejssig
[RFC8032]: https://tools.ietf.org/html/rfc8032
[zebra]: https://github.com/ZcashFoundation/zebra
