//! The issuer's Ed25519 key. It signs every `POST /v2/redeem` answer
//! (docs/CREDITS.md "Issuer API"), and the PIR servers pin its public key
//! with `--credit-issuer-pubkey`. The seed is the file `bpir-issuer keygen`
//! writes (`grant.key` in production: the name predates credits, and the
//! public key is the one the servers already pin).

use ed25519_dalek::{Signer, SigningKey};

pub struct IssuerKey {
    key: SigningKey,
}

impl IssuerKey {
    pub fn new(seed: &[u8; 32]) -> Self {
        Self {
            key: SigningKey::from_bytes(seed),
        }
    }

    /// Sign a redeem answer preimage.
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.key.sign(message).to_bytes()
    }

    pub fn public_key(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }

    pub fn public_key_hex(&self) -> String {
        hex::encode(self.public_key())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    #[test]
    fn answers_verify_under_the_published_key() {
        let key = IssuerKey::new(&[7u8; 32]);
        let signature = Signature::from_bytes(&key.sign(b"answer"));
        let public = VerifyingKey::from_bytes(&key.public_key()).unwrap();
        public.verify(b"answer", &signature).unwrap();
        assert!(public.verify(b"other", &signature).is_err());
        assert_eq!(key.public_key_hex(), hex::encode(public.to_bytes()));
    }
}
