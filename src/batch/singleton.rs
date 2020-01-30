use std::{
    convert::TryFrom,
    task::{Context, Poll},
};

use tower_service::Service;

use crate::{batch::VerificationRequest, Error, PublicKey};

/// Performs singleton Ed25519 signature verification.
///
/// This wraps the normal single-signature verification functions in a
/// [`Service`] implementation, allowing users to abstract over singleton and
/// batch verification.
#[derive(Default)]
pub struct SingletonVerifier;

impl Service<VerificationRequest<'_>> for SingletonVerifier {
    type Response = ();
    type Error = Error;
    type Future = futures::future::Ready<Result<(), Error>>;

    fn poll_ready(&mut self, _cx: &mut Context) -> Poll<Result<(), Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: VerificationRequest) -> Self::Future {
        let (pk_bytes, sig, msg) = req;

        futures::future::ready(PublicKey::try_from(pk_bytes).and_then(|pk| pk.verify(&sig, msg)))
    }
}
