/// An Ed25519 signature.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[allow(non_snake_case)]
pub struct Signature {
    pub(crate) R_bytes: [u8; 32],
    pub(crate) s_bytes: [u8; 32],
}

impl From<[u8; 64]> for Signature {
    #[allow(non_snake_case)]
    fn from(bytes: [u8; 64]) -> Signature {
        let mut R_bytes = [0; 32];
        R_bytes.copy_from_slice(&bytes[0..32]);
        let mut s_bytes = [0; 32];
        s_bytes.copy_from_slice(&bytes[32..64]);
        Signature { R_bytes, s_bytes }
    }
}

impl From<Signature> for [u8; 64] {
    fn from(sig: Signature) -> [u8; 64] {
        let mut bytes = [0; 64];
        bytes[0..32].copy_from_slice(&sig.R_bytes[..]);
        bytes[32..64].copy_from_slice(&sig.s_bytes[..]);
        bytes
    }
}