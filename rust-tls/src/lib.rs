//! TLS for a socket the Workers runtime will not encrypt for us.
//!
//! `startTls({ expectedServerHostname })` is the obvious way to secure a
//! tunnelled connection, but workerd logs that option as unsupported and has an
//! autogate ready to reject it outright, so a proxied request cannot rely on
//! it. This crate puts rustls behind a small state machine instead: JavaScript
//! owns the socket and pumps bytes through, and nothing here does any I/O.

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
use rustls::fingerprint::Fingerprint;
use rustls::{
    CipherSuite, ClientConfig, ClientConnection, DigitallySignedStruct, DistinguishedName, Error,
    RootCertStore, SignatureScheme,
};
use rustls_pki_types::{CertificateDer, ServerName, UnixTime};
use std::io::{Cursor, Read, Write};
use std::sync::{Arc, Mutex};
use wasm_bindgen::prelude::*;

fn fail(context: &str, error: impl std::fmt::Display) -> JsValue {
    JsValue::from_str(&format!("{context}: {error}"))
}

/// Splits `(length u32, DER)` records, the shape certificates cross the
/// boundary in either way.
fn certificates_from(blob: &[u8]) -> Vec<CertificateDer<'static>> {
    let mut out = Vec::new();
    let mut at = 0;
    while at + 4 <= blob.len() {
        let len = u32::from_be_bytes([blob[at], blob[at + 1], blob[at + 2], blob[at + 3]]) as usize;
        at += 4;
        if at + len > blob.len() {
            break;
        }
        out.push(CertificateDer::from(blob[at..at + len].to_vec()));
        at += len;
    }
    out
}

/// The web PKI's own verifier, given two things a browser has and it lacks:
/// intermediates fetched from elsewhere, and a record of what the server sent.
///
/// A server that sends its leaf alone loads in a browser, because the browser
/// fetches the missing issuer from the address the certificate names (its AIA
/// extension). The caller does that fetching; this only widens the pool of
/// intermediates a path may be built from. The path must still end at a
/// trusted root and every other check still applies, so an extra certificate
/// can complete a chain but never excuse a bad one.
#[derive(Debug)]
struct Completing {
    inner: Arc<WebPkiServerVerifier>,
    extra: Vec<CertificateDer<'static>>,
    presented: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl ServerCertVerifier for Completing {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        if let Ok(mut presented) = self.presented.lock() {
            *presented = std::iter::once(end_entity)
                .chain(intermediates)
                .map(|cert| cert.to_vec())
                .collect();
        }
        let mut pool: Vec<CertificateDer<'_>> = intermediates.to_vec();
        pool.extend(self.extra.iter().cloned());
        self.inner
            .verify_server_cert(end_entity, &pool, server_name, ocsp_response, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.inner
            .verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.inner
            .verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }

    fn root_hint_subjects(&self) -> Option<&[DistinguishedName]> {
        self.inner.root_hint_subjects()
    }
}

#[wasm_bindgen]
pub struct TlsClient {
    conn: ClientConnection,
    presented: Arc<Mutex<Vec<Vec<u8>>>>,
}

#[wasm_bindgen]
impl TlsClient {
    /// A client that will accept only a certificate valid for `hostname`,
    /// whatever address the underlying socket was opened to.
    ///
    /// The last three arguments shape the ClientHello, and come from the
    /// caller rather than from here: adding a browser is then a table of
    /// numbers in TypeScript instead of a rebuild of this crate. Leave them
    /// out and rustls makes its own choices, which are safe and instantly
    /// recognisable as rustls.
    #[wasm_bindgen(constructor)]
    pub fn new(
        hostname: &str,
        alpn: Option<String>,
        ciphers: Option<Vec<u16>>,
        signature_schemes: Option<Vec<u16>>,
        extensions: Option<Vec<u8>>,
        grease_named_group: Option<bool>,
        extension_order: Option<Vec<u16>>,
        named_groups: Option<Vec<u16>>,
        intermediates: Option<Vec<u8>>,
        verifiable_signatures: Option<bool>,
    ) -> Result<TlsClient, JsValue> {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        let inner = WebPkiServerVerifier::builder_with_provider(
            Arc::new(roots),
            Arc::new(rustls::crypto::ring::default_provider()),
        )
        .build()
        .map_err(|error| fail("could not build the certificate verifier", error))?;
        // The schemes this verifier can check. A browser offers more — SHA-1,
        // and ECDSA with SHA-512 — and an old TLS 1.2 server that picks one
        // cannot be verified. Asked for, the offer is cut to what can be.
        let verifiable = inner.supported_verify_schemes();
        let presented = Arc::new(Mutex::new(Vec::new()));
        let verifier = Completing {
            inner,
            extra: certificates_from(&intermediates.unwrap_or_default()),
            presented: presented.clone(),
        };

        let mut config = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verifier))
            .with_no_client_auth();
        if let Some(list) = alpn {
            config.alpn_protocols = list
                .split(',')
                .filter(|name| !name.is_empty())
                .map(|name| name.as_bytes().to_vec())
                .collect();
        }

        let fingerprint = Fingerprint {
            cipher_suites: ciphers
                .unwrap_or_default()
                .into_iter()
                .map(CipherSuite::from)
                .collect(),
            signature_schemes: signature_schemes
                .unwrap_or_default()
                .into_iter()
                .map(SignatureScheme::from)
                .filter(|scheme| !verifiable_signatures.unwrap_or(false) || verifiable.contains(scheme))
                .collect(),
            verbatim_extensions: Fingerprint::extensions_from_bytes(&extensions.unwrap_or_default()),
            // Firefox GREASEs nothing at all, so this cannot be inferred.
            grease_named_group: grease_named_group.unwrap_or(false),
            extension_order: extension_order.unwrap_or_default(),
            named_groups: named_groups.unwrap_or_default(),
        };
        if !fingerprint.cipher_suites.is_empty()
            || !fingerprint.signature_schemes.is_empty()
            || !fingerprint
                .verbatim_extensions
                .is_empty()
            || !fingerprint.extension_order.is_empty()
            || !fingerprint.named_groups.is_empty()
        {
            config.fingerprint = Some(Arc::new(fingerprint));
        }

        let name = ServerName::try_from(hostname.to_string())
            .map_err(|error| fail("invalid hostname", error))?
            .to_owned();
        let conn = ClientConnection::new(Arc::new(config), name)
            .map_err(|error| fail("could not start TLS", error))?;
        Ok(TlsClient { conn, presented })
    }

    /// Hands over bytes that arrived from the network and returns how many were
    /// taken. One call does not always consume the whole slice, so the caller
    /// must loop from the returned offset or it will silently drop data.
    pub fn receive(&mut self, data: &[u8]) -> Result<usize, JsValue> {
        let taken = self
            .conn
            .read_tls(&mut Cursor::new(data))
            .map_err(|error| fail("TLS read failed", error))?;
        self.conn
            .process_new_packets()
            .map_err(|error| fail("TLS session failed", error))?;
        Ok(taken)
    }

    /// Ciphertext waiting to go out on the socket. Empty when there is none.
    pub fn outgoing(&mut self) -> Result<Vec<u8>, JsValue> {
        let mut out = Vec::new();
        while self.conn.wants_write() {
            self.conn
                .write_tls(&mut out)
                .map_err(|error| fail("TLS write failed", error))?;
        }
        Ok(out)
    }

    /// Queues plaintext for encryption; read it back out with `outgoing`.
    pub fn send(&mut self, data: &[u8]) -> Result<(), JsValue> {
        self.conn
            .writer()
            .write_all(data)
            .map_err(|error| fail("could not queue plaintext", error))
    }

    /// Plaintext decrypted so far. Empty when the peer has sent nothing new.
    pub fn plaintext(&mut self) -> Result<Vec<u8>, JsValue> {
        let mut out = Vec::new();
        let mut buffer = [0u8; 8192];
        loop {
            match self.conn.reader().read(&mut buffer) {
                Ok(0) => break,
                Ok(read) => out.extend_from_slice(&buffer[..read]),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(error) => return Err(fail("could not read plaintext", error)),
            }
        }
        Ok(out)
    }

    #[wasm_bindgen(getter)]
    pub fn handshaking(&self) -> bool {
        self.conn.is_handshaking()
    }

    /// The protocol the server picked from the ALPN list, if any.
    #[wasm_bindgen(getter)]
    pub fn protocol(&self) -> Option<String> {
        self.conn
            .alpn_protocol()
            .map(|name| String::from_utf8_lossy(name).into_owned())
    }

    /// The certificates the server sent, leaf first, as `(length u32, DER)`
    /// records. Filled in when the chain is checked, whether or not it passed,
    /// so a caller can look for the issuer a failed chain was missing.
    #[wasm_bindgen(js_name = presentedChain)]
    pub fn presented_chain(&self) -> Vec<u8> {
        let mut out = Vec::new();
        if let Ok(presented) = self.presented.lock() {
            for cert in presented.iter() {
                out.extend_from_slice(&(cert.len() as u32).to_be_bytes());
                out.extend_from_slice(cert);
            }
        }
        out
    }

    /// Starts a clean shutdown; the caller still has to flush `outgoing`.
    pub fn close(&mut self) {
        self.conn.send_close_notify();
    }
}
