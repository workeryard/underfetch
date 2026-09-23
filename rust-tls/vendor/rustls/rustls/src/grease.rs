//! FORK: making the ClientHello look like a browser's.
//!
//! Two things separate a stock rustls handshake from Chrome's. First, GREASE
//! (RFC 8701): browsers scatter reserved values through the ClientHello so that
//! servers stay tolerant of what they do not know, and rustls sends none, which
//! is the single most recognisable thing about it. Second, Chrome offers cipher
//! suites and extensions rustls has no use for.
//!
//! Suites we advertise but cannot negotiate are a deliberate gamble: a server
//! that chose one would fail the handshake, but Chrome lists the TLS 1.3 suites
//! first and servers take them. Extensions here are written verbatim and never
//! read back, so offering one costs nothing.
//!
//! The reference is Chrome 133 as recorded by utls (`u_parrots.go`).

use alloc::vec;
use alloc::vec::Vec;

use crate::crypto::{GetRandomFailed, SecureRandom};
use crate::enums::{CipherSuite, SignatureScheme};
use crate::msgs::enums::NamedGroup;

/// The sixteen reserved values, each of the form 0x?A?A.
const VALUES: [u16; 16] = [
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
    0xcaca, 0xdada, 0xeaea, 0xfafa,
];

/// A fixed value for now: a handshake has no randomness to hand here, and a
/// constant is what makes the change visible in a fingerprint test.
const CHOSEN: u16 = VALUES[0];

pub(crate) fn named_group() -> NamedGroup {
    NamedGroup::Unknown(CHOSEN)
}

/// Chrome's cipher list, in Chrome's order. The last six are TLS 1.2 CBC and
/// RSA suites rustls will not implement; they are offered, never accepted.
pub(crate) fn cipher_suites() -> Vec<CipherSuite> {
    [
        CHOSEN, // GREASE leads
        0x1301, 0x1302, 0x1303, // TLS 1.3
        0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, // ECDHE with AEAD
        0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035, // offered only
    ]
    .into_iter()
    .map(CipherSuite::from)
    .collect()
}

/// Chrome's signature algorithms, in Chrome's order. rustls would otherwise
/// offer its own set, which is longer and includes ed25519.
pub(crate) fn signature_schemes() -> Vec<SignatureScheme> {
    [
        0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
    ]
    .into_iter()
    .map(SignatureScheme::from)
    .collect()
}

/// A GREASE ECH extension, shaped like the real thing a browser sends but
/// carrying nothing: an outer ECH with an X25519 key and a payload of noise.
///
/// The bytes are freshly random every handshake. A fixed payload would itself
/// become a fingerprint, which is the opposite of the point.
fn ech(random: &dyn SecureRandom) -> Result<Vec<u8>, GetRandomFailed> {
    const ENC: usize = 32; // an X25519 public key
    const PAYLOAD: usize = 176; // what Chrome's GREASE payload runs to

    let mut body = Vec::with_capacity(10 + ENC + PAYLOAD);
    let mut config_id = [0u8; 1];
    random.fill(&mut config_id)?;

    body.push(0x00); // outer
    body.extend_from_slice(&0x0001u16.to_be_bytes()); // HKDF-SHA256
    body.extend_from_slice(&0x0001u16.to_be_bytes()); // AES-128-GCM
    body.push(config_id[0]);

    let mut noise = vec![0u8; ENC + PAYLOAD];
    random.fill(&mut noise)?;
    body.extend_from_slice(&(ENC as u16).to_be_bytes());
    body.extend_from_slice(&noise[..ENC]);
    body.extend_from_slice(&(PAYLOAD as u16).to_be_bytes());
    body.extend_from_slice(&noise[ENC..]);
    Ok(body)
}

/// Extensions Chrome sends that rustls does not build, as `(type, body)`.
///
/// - `0xff01` renegotiation_info, carrying an empty connection id.
/// - `0x0012` signed_certificate_timestamp, which is empty by definition.
/// - `0x001b` compress_certificate, offering brotli (algorithm 2).
/// - `0x44cd` application_settings (ALPS), naming `h2`.
/// - `0xfe0d` encrypted_client_hello, GREASE only.
///
/// Two GREASE extensions bracket the list, as they do in a browser. A failure
/// to draw randomness drops only the ECH extension: a handshake that works is
/// worth more than one that matches.
pub(crate) fn extensions(random: &dyn SecureRandom) -> Vec<(u16, Vec<u8>)> {
    let mut exts = vec![
        (CHOSEN, vec![]),
        (0xff01, vec![0x00]),
        (0x0012, vec![]),
        (0x001b, vec![0x02, 0x00, 0x02]),
        (0x44cd, vec![0x00, 0x03, 0x02, b'h', b'2']),
    ];
    if let Ok(body) = ech(random) {
        exts.push((0xfe0d, body));
    }
    exts.push((VALUES[1], vec![0x00]));
    exts
}
