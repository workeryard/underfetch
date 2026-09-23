//! FORK: GREASE values (RFC 8701).
//!
//! Browsers scatter reserved values through the ClientHello so that servers
//! stay tolerant of extensions they do not know. rustls sends none, which is
//! the single most recognisable thing about its handshake: a fingerprint does
//! not need to understand the value, only to notice that nobody else omits it.
//!
//! A server is required to ignore these, so they cost nothing but bytes.

use crate::enums::CipherSuite;
use crate::msgs::enums::NamedGroup;

/// The sixteen reserved values, each of the form 0x?A?A.
const VALUES: [u16; 16] = [
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
    0xcaca, 0xdada, 0xeaea, 0xfafa,
];

/// A fixed value for now: a handshake has no randomness to hand here, and a
/// constant is what makes the change visible in a fingerprint test.
const CHOSEN: u16 = VALUES[0];

pub(crate) fn cipher_suite() -> CipherSuite {
    CipherSuite::Unknown(CHOSEN)
}

pub(crate) fn named_group() -> NamedGroup {
    NamedGroup::Unknown(CHOSEN)
}

/// The GREASE extensions a browser brackets its extension list with: an empty
/// one, and a second, different value carrying a single zero byte. Both are
/// written verbatim and never read back.
pub(crate) fn extensions() -> alloc::vec::Vec<(u16, alloc::vec::Vec<u8>)> {
    alloc::vec![(CHOSEN, alloc::vec![]), (VALUES[1], alloc::vec![0x00])]
}
