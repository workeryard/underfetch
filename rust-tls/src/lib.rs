//! TLS for a socket the Workers runtime will not encrypt for us.
//!
//! `startTls({ expectedServerHostname })` is the obvious way to secure a
//! tunnelled connection, but workerd logs that option as unsupported and has an
//! autogate ready to reject it outright, so a proxied request cannot rely on
//! it. This crate puts rustls behind a small state machine instead: JavaScript
//! owns the socket and pumps bytes through, and nothing here does any I/O.

use rustls::fingerprint::Fingerprint;
use rustls::{CipherSuite, ClientConfig, ClientConnection, RootCertStore, SignatureScheme};
use rustls_pki_types::ServerName;
use std::io::{Cursor, Read, Write};
use std::sync::Arc;
use wasm_bindgen::prelude::*;

fn fail(context: &str, error: impl std::fmt::Display) -> JsValue {
    JsValue::from_str(&format!("{context}: {error}"))
}

#[wasm_bindgen]
pub struct TlsClient {
    conn: ClientConnection,
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
    ) -> Result<TlsClient, JsValue> {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        let mut config = ClientConfig::builder()
            .with_root_certificates(roots)
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
        Ok(TlsClient { conn })
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

    /// Starts a clean shutdown; the caller still has to flush `outgoing`.
    pub fn close(&mut self) {
        self.conn.send_close_notify();
    }
}
