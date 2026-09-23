//! FORK: letting the caller decide what the ClientHello looks like.
//!
//! A stock rustls handshake is recognisable at a glance: it sends no GREASE
//! (RFC 8701), and nothing else on the web omits it. Matching a browser needs
//! more than that — its cipher list, its signature algorithms, and extensions
//! rustls has no use for.
//!
//! None of that is decided here. A [`Fingerprint`] is handed in from outside,
//! so a new browser is a table of numbers somewhere else rather than a change
//! to this crate. Left unset, rustls behaves as it always did.
//!
//! Two things make this survivable. Suites can be advertised without being
//! implemented: a server that chose one would fail the handshake, but browsers
//! list the TLS 1.3 suites first and servers take them. And verbatim
//! extensions are only ever written, never parsed, so offering one costs
//! nothing.

use alloc::vec::Vec;

use crate::enums::{CipherSuite, SignatureScheme};
use crate::msgs::enums::NamedGroup;

/// The sixteen reserved values of RFC 8701, each of the form 0x?A?A.
const GREASE: [u16; 16] = [
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
    0xcaca, 0xdada, 0xeaea, 0xfafa,
];

/// True for a GREASE value, which a fingerprint strips before hashing.
pub(crate) fn is_grease(value: u16) -> bool {
    GREASE.contains(&value)
}

/// What a ClientHello should offer, and in what order.
#[derive(Clone, Debug, Default)]
pub struct Fingerprint {
    /// Offered verbatim, including any GREASE. Empty leaves rustls' own list.
    pub cipher_suites: Vec<CipherSuite>,
    /// Offered verbatim. Empty leaves the verifier's own list.
    pub signature_schemes: Vec<SignatureScheme>,
    /// `(type, body)` pairs written as they are and never read back.
    pub verbatim_extensions: Vec<(u16, Vec<u8>)>,
    /// Puts a GREASE value at the head of the supported groups, as a browser does.
    pub grease_named_group: bool,
}

impl Fingerprint {
    /// Parses `(type u16, length u16, body)` triples, the shape a caller can
    /// build without knowing anything about this crate's types.
    pub fn extensions_from_bytes(encoded: &[u8]) -> Vec<(u16, Vec<u8>)> {
        let mut out = Vec::new();
        let mut at = 0;
        while at + 4 <= encoded.len() {
            let typ = u16::from_be_bytes([encoded[at], encoded[at + 1]]);
            let len = u16::from_be_bytes([encoded[at + 2], encoded[at + 3]]) as usize;
            at += 4;
            if at + len > encoded.len() {
                break;
            }
            out.push((typ, encoded[at..at + len].to_vec()));
            at += len;
        }
        out
    }

    pub(crate) fn named_group(&self) -> Option<NamedGroup> {
        match self.grease_named_group {
            true => Some(NamedGroup::Unknown(GREASE[0])),
            false => None,
        }
    }
}
