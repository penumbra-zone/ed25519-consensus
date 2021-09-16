# Ed25519 for consensus-critical contexts

This library provides an Ed25519 implementation with validation rules intended
for consensus-critical contexts.

```toml
ed25519-consensus = "1"
```

Ed25519 signatures are widely used in consensus-critical contexts (e.g.,
blockchains), where different nodes must agree on whether or not a given
signature is valid.  However, Ed25519 does not clearly define criteria for
signature validity, and even standards-conformant implementations are not
required to agree on whether a signature is valid.

Different Ed25519 implementations may not (and in practice, do not) agree on
validation criteria in subtle edge cases.   This poses a double risk to the use
of Ed25519 in consensus-critical contexts.  First, the presence of multiple
Ed25519 implementations may open the possibility of consensus divergence.
Second, even when a single implementation is used, the protocol implicitly
includes that particular version's validation criteria as part of the consensus
rules.  However, if the implementation is not intended to be used in
consensus-critical contexts, it may change validation criteria between releases.

For instance, the initial implementation of Zcash consensus in zcashd inherited
validity criteria from a then-current version of libsodium (1.0.15). Due to a
bug in libsodium, this was different from the intended criteria documented in
the Zcash protocol specification 3 (before the specification was changed to
match libsodium 1.0.15 in specification version 2020.1.2). Also, libsodium never
guaranteed stable validity criteria, and changed behavior in a later point
release. This forced zcashd to use an older version of the library before
eventually patching a newer version to have consistent validity criteria. To be
compatible, [Zebra] had to implement a special library, `ed25519-zebra`, to
provide Zcash-flavored Ed25519, attempting to match libsodium 1.0.15 exactly.
And the initial attempt to implement `ed25519-zebra` was also incompatible,
because it precisely matched the wrong compile-time configuration of libsodium.

This problem is fixed by [ZIP215], a specification of a precise set of
validation criteria for Ed25519 signatures.  Although originally developed for
Zcash, these rules are of general interest, as they precisely specified and
ensure that batch and individual verification are guaranteed to give the same
results.  This library implements these rules; it is a fork of `ed25519-zebra`
with Zcash-specific parts removed.

More details on this problem and its solution can be found in [*It's 255:19AM.
Do you know what your validation criteria are?*][blog]

## Example

```
use std::convert::TryFrom;
use rand::thread_rng;
use ed25519_consensus::*;

let msg = b"ed25519-consensus";

// Signer's context
let (vk_bytes, sig_bytes) = {
    // Generate a signing key and sign the message
    let sk = SigningKey::new(thread_rng());
    let sig = sk.sign(msg);

    // Types can be converted to raw byte arrays with From/Into
    let sig_bytes: [u8; 64] = sig.into();
    let vk_bytes: [u8; 32] = VerificationKey::from(&sk).into();

    (vk_bytes, sig_bytes)
};

// Verify the signature
assert!(
    VerificationKey::try_from(vk_bytes)
        .and_then(|vk| vk.verify(&sig_bytes.into(), msg))
        .is_ok()
);
```

[zcash_protocol_jssig]: https://zips.z.cash/protocol/protocol.pdf#concretejssig
[RFC8032]: https://tools.ietf.org/html/rfc8032
[zebra]: https://github.com/ZcashFoundation/zebra
[ZIP215]: https://github.com/zcash/zips/blob/master/zip-0215.rst
[blog]: https://hdevalence.ca/blog/2020-10-04-its-25519am