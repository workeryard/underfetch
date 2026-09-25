//! X25519MLKEM768, the post-quantum hybrid every current browser leads its key
//! share with.
//!
//! ring has no ML-KEM, and rustls' own hybrid sits on aws-lc-rs, which does
//! not build for wasm32-unknown-unknown. So the ML-KEM half comes from
//! RustCrypto's `ml-kem` (FIPS 203) and the X25519 half from ring, joined as
//! draft-ietf-tls-ecdhe-mlkem joins them: the ML-KEM part first in both
//! shares and in the secret. Only the client side exists here.
//!
//! `hybrid_component()` is what makes rustls also send a plain X25519 share
//! beside the hybrid one, as Chrome, Firefox and Safari do, and complete that
//! one alone when a server picks X25519.

use ml_kem::kem::Decapsulate;
use ml_kem::{Ciphertext, EncodedSizeUser, KemCore, MlKem768};
use rand_core::OsRng;
use rustls::crypto::{ActiveKeyExchange, SharedSecret, SupportedKxGroup};
use rustls::ffdhe_groups::FfdheGroup;
use rustls::{Error, NamedGroup, PeerMisbehaved, ProtocolVersion};

const MLKEM768_ENCAPSULATION_KEY_LEN: usize = 1184;
const MLKEM768_CIPHERTEXT_LEN: usize = 1088;
const X25519_LEN: usize = 32;

const INVALID_KEY_SHARE: Error = Error::PeerMisbehaved(PeerMisbehaved::InvalidKeyShare);

#[derive(Debug)]
pub struct X25519MlKem768;

pub static X25519MLKEM768: &dyn SupportedKxGroup = &X25519MlKem768;

impl SupportedKxGroup for X25519MlKem768 {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        let classical = rustls::crypto::ring::kx_group::X25519.start()?;
        let (decapsulation, encapsulation) = MlKem768::generate(&mut OsRng);
        let encoded = encapsulation.as_bytes();
        debug_assert_eq!(encoded.len(), MLKEM768_ENCAPSULATION_KEY_LEN);
        let mut pub_key = Vec::with_capacity(MLKEM768_ENCAPSULATION_KEY_LEN + X25519_LEN);
        pub_key.extend_from_slice(&encoded);
        pub_key.extend_from_slice(classical.pub_key());
        Ok(Box::new(Active {
            classical,
            decapsulation,
            pub_key,
        }))
    }

    fn ffdhe_group(&self) -> Option<FfdheGroup<'static>> {
        None
    }

    fn name(&self) -> NamedGroup {
        NamedGroup::X25519MLKEM768
    }

    fn usable_for_version(&self, version: ProtocolVersion) -> bool {
        version == ProtocolVersion::TLSv1_3
    }
}

struct Active {
    classical: Box<dyn ActiveKeyExchange>,
    decapsulation: <MlKem768 as KemCore>::DecapsulationKey,
    pub_key: Vec<u8>,
}

impl ActiveKeyExchange for Active {
    /// The server's share is the ML-KEM ciphertext, then its X25519 key; the
    /// secret is the ML-KEM one, then the X25519 one.
    fn complete(self: Box<Self>, peer_pub_key: &[u8]) -> Result<SharedSecret, Error> {
        if peer_pub_key.len() != MLKEM768_CIPHERTEXT_LEN + X25519_LEN {
            return Err(INVALID_KEY_SHARE);
        }
        let (ciphertext, classical_share) = peer_pub_key.split_at(MLKEM768_CIPHERTEXT_LEN);
        let ciphertext =
            Ciphertext::<MlKem768>::try_from(ciphertext).map_err(|_| INVALID_KEY_SHARE)?;
        let post_quantum = self
            .decapsulation
            .decapsulate(&ciphertext)
            .map_err(|_| INVALID_KEY_SHARE)?;
        let classical = self.classical.complete(classical_share)?;
        let mut secret = Vec::with_capacity(64);
        secret.extend_from_slice(&post_quantum);
        secret.extend_from_slice(classical.secret_bytes());
        Ok(SharedSecret::from(secret))
    }

    fn hybrid_component(&self) -> Option<(NamedGroup, &[u8])> {
        Some((self.classical.group(), self.classical.pub_key()))
    }

    fn complete_hybrid_component(
        self: Box<Self>,
        peer_pub_key: &[u8],
    ) -> Result<SharedSecret, Error> {
        self.classical.complete(peer_pub_key)
    }

    fn pub_key(&self) -> &[u8] {
        &self.pub_key
    }

    fn ffdhe_group(&self) -> Option<FfdheGroup<'static>> {
        None
    }

    fn group(&self) -> NamedGroup {
        NamedGroup::X25519MLKEM768
    }
}

/// A group with a P-256 share sent after its own, as Firefox sends them:
/// X25519MLKEM768, its X25519 component, then P-256 — or, for Tor, X25519
/// then P-256. A server that picks P-256 is answered with that share.
#[derive(Debug)]
pub struct ThenP256 {
    lead: &'static dyn SupportedKxGroup,
}

pub static X25519MLKEM768_THEN_P256: &dyn SupportedKxGroup = &ThenP256 {
    lead: &X25519MlKem768,
};

pub static X25519_THEN_P256: &dyn SupportedKxGroup = &ThenP256 {
    lead: rustls::crypto::ring::kx_group::X25519,
};

impl SupportedKxGroup for ThenP256 {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        Ok(Box::new(WithExtras {
            inner: self.lead.start()?,
            extras: vec![rustls::crypto::ring::kx_group::SECP256R1.start()?],
        }))
    }

    fn ffdhe_group(&self) -> Option<FfdheGroup<'static>> {
        None
    }

    fn name(&self) -> NamedGroup {
        self.lead.name()
    }

    fn usable_for_version(&self, version: ProtocolVersion) -> bool {
        version == ProtocolVersion::TLSv1_3
    }
}

struct WithExtras {
    inner: Box<dyn ActiveKeyExchange>,
    extras: Vec<Box<dyn ActiveKeyExchange>>,
}

impl ActiveKeyExchange for WithExtras {
    fn complete(self: Box<Self>, peer_pub_key: &[u8]) -> Result<SharedSecret, Error> {
        self.inner.complete(peer_pub_key)
    }

    fn hybrid_component(&self) -> Option<(NamedGroup, &[u8])> {
        self.inner.hybrid_component()
    }

    fn complete_hybrid_component(
        self: Box<Self>,
        peer_pub_key: &[u8],
    ) -> Result<SharedSecret, Error> {
        self.inner.complete_hybrid_component(peer_pub_key)
    }

    fn extra_shares(&self) -> Vec<(NamedGroup, &[u8])> {
        self.extras
            .iter()
            .map(|extra| (extra.group(), extra.pub_key()))
            .collect()
    }

    fn complete_extra_share(
        self: Box<Self>,
        group: NamedGroup,
        peer_pub_key: &[u8],
    ) -> Result<SharedSecret, Error> {
        let extra = self
            .extras
            .into_iter()
            .find(|extra| extra.group() == group)
            .ok_or(INVALID_KEY_SHARE)?;
        extra.complete(peer_pub_key)
    }

    fn pub_key(&self) -> &[u8] {
        self.inner.pub_key()
    }

    fn ffdhe_group(&self) -> Option<FfdheGroup<'static>> {
        None
    }

    fn group(&self) -> NamedGroup {
        self.inner.group()
    }
}
