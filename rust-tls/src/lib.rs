//! TLS for a socket the Workers runtime will not encrypt for us.
//!
//! `startTls({ expectedServerHostname })` is the obvious way to secure a
//! tunnelled connection, but workerd logs that option as unsupported and has an
//! autogate ready to reject it outright, so a proxied request cannot rely on
//! it. This crate puts rustls behind a small state machine instead: JavaScript
//! owns the socket and pumps bytes through, and nothing here does any I/O.

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::{
    ClientSessionMemoryCache, ResolvesClientCert, ClientSessionStore, Resumption, Tls12ClientSessionValue,
    Tls13ClientSessionValue, WebPkiServerVerifier,
};
use rustls::fingerprint::Fingerprint;
use rustls::sign::CertifiedKey;
use rustls::{
    CipherSuite, ClientConfig, ClientConnection, DigitallySignedStruct, DistinguishedName, Error,
    NamedGroup, RootCertStore, SignatureScheme,
};
use rustls_pki_types::{CertificateDer, ServerName, UnixTime};
use std::cell::{Cell, RefCell};
use std::collections::HashMap;
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
///
/// One verifier serves every connection of a `TicketStore`, because rustls
/// resumes a ticket only under the very verifier that issued it. What differs
/// between connections is the `Context`, which a `TlsClient` puts in place
/// before each batch of bytes it processes: JavaScript is single-threaded, and
/// verification happens inside that one synchronous call, so no other
/// connection's handshake can run in between.
#[derive(Debug)]
struct Completing {
    inner: Arc<WebPkiServerVerifier>,
    current: Mutex<Context>,
}

/// One connection's share of the verifier: the intermediates fetched for it,
/// and where to record the chain its server presents.
#[derive(Debug, Clone, Default)]
struct Context {
    extra: Arc<Vec<CertificateDer<'static>>>,
    presented: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl Completing {
    fn new() -> Result<Completing, JsValue> {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let inner = WebPkiServerVerifier::builder_with_provider(
            Arc::new(roots),
            Arc::new(rustls::crypto::ring::default_provider()),
        )
        .build()
        .map_err(|error| fail("could not build the certificate verifier", error))?;
        Ok(Completing { inner, current: Mutex::new(Context::default()) })
    }

    fn enter(&self, context: &Context) {
        if let Ok(mut current) = self.current.lock() {
            *current = context.clone();
        }
    }
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
        let context = self.current.lock().map(|c| c.clone()).unwrap_or_default();
        if let Ok(mut presented) = context.presented.lock() {
            *presented = std::iter::once(end_entity)
                .chain(intermediates)
                .map(|cert| cert.to_vec())
                .collect();
        }
        let mut pool: Vec<CertificateDer<'_>> = intermediates.to_vec();
        pool.extend(context.extra.iter().cloned());
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

/// Session tickets, kept so a second connection to a host resumes the first
/// as a returning browser does. One per `Session` on the JavaScript side, so
/// nothing links one caller's connections to another's.
///
/// rustls' own store also remembers which key-exchange group each server
/// chose and leads the next ClientHello's key share with it. A browser does
/// not — Chrome leads with X25519 every time — so that half is dropped here,
/// and only the tickets are kept.
///
/// JavaScript holds the store by its `id`, which a `TlsClient` is handed;
/// wasm-bindgen cannot pass an optional reference to one of its own objects.
/// Dropping the store, which wasm-bindgen does when its JavaScript object is
/// collected, forgets the tickets.
#[wasm_bindgen]
pub struct TicketStore {
    id: u32,
}

/// What the connections of one store share: the tickets, and the verifier
/// and client-certificate resolver rustls checks a ticket against.
#[derive(Clone)]
struct Shared {
    tickets: Arc<TicketsOnly>,
    verifier: Arc<Completing>,
    creds: Arc<dyn ResolvesClientCert>,
}

thread_local! {
    static STORES: RefCell<HashMap<u32, Shared>> = RefCell::new(HashMap::new());
    static NEXT_ID: Cell<u32> = const { Cell::new(1) };
}

#[wasm_bindgen]
impl TicketStore {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Result<TicketStore, JsValue> {
        let id = NEXT_ID.with(|next| {
            let id = next.get();
            next.set(id.wrapping_add(1).max(1));
            id
        });
        let shared = Shared {
            // As many hosts as rustls' own default cache holds.
            tickets: Arc::new(TicketsOnly(ClientSessionMemoryCache::new(256))),
            verifier: Arc::new(Completing::new()?),
            creds: Arc::new(NoClientCert),
        };
        STORES.with(|stores| stores.borrow_mut().insert(id, shared));
        Ok(TicketStore { id })
    }

    #[wasm_bindgen(getter)]
    pub fn id(&self) -> u32 {
        self.id
    }
}

impl Drop for TicketStore {
    fn drop(&mut self) {
        STORES.with(|stores| stores.borrow_mut().remove(&self.id));
    }
}

/// We never present a client certificate; this says so, as one object a
/// store's connections can share.
#[derive(Debug)]
struct NoClientCert;

impl ResolvesClientCert for NoClientCert {
    fn resolve(&self, _: &[&[u8]], _: &[SignatureScheme]) -> Option<Arc<CertifiedKey>> {
        None
    }

    fn has_certs(&self) -> bool {
        false
    }
}

#[derive(Debug)]
struct TicketsOnly(ClientSessionMemoryCache);

impl ClientSessionStore for TicketsOnly {
    fn set_kx_hint(&self, _: ServerName<'static>, _: NamedGroup) {}

    fn kx_hint(&self, _: &ServerName<'_>) -> Option<NamedGroup> {
        None
    }

    fn set_tls12_session(&self, name: ServerName<'static>, value: Tls12ClientSessionValue) {
        self.0.set_tls12_session(name, value);
    }

    fn tls12_session(&self, name: &ServerName<'_>) -> Option<Tls12ClientSessionValue> {
        self.0.tls12_session(name)
    }

    fn remove_tls12_session(&self, name: &ServerName<'static>) {
        self.0.remove_tls12_session(name);
    }

    fn insert_tls13_ticket(&self, name: ServerName<'static>, value: Tls13ClientSessionValue) {
        self.0.insert_tls13_ticket(name, value);
    }

    fn take_tls13_ticket(&self, name: &ServerName<'static>) -> Option<Tls13ClientSessionValue> {
        self.0.take_tls13_ticket(name)
    }
}

#[wasm_bindgen]
pub struct TlsClient {
    conn: ClientConnection,
    verifier: Arc<Completing>,
    context: Context,
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
        tickets: Option<u32>,
    ) -> Result<TlsClient, JsValue> {
        let shared = tickets.and_then(|id| STORES.with(|stores| stores.borrow().get(&id).cloned()));
        let verifier = match &shared {
            Some(shared) => shared.verifier.clone(),
            None => Arc::new(Completing::new()?),
        };
        // The schemes this verifier can check. A browser offers more — SHA-1,
        // and ECDSA with SHA-512 — and an old TLS 1.2 server that picks one
        // cannot be verified. Asked for, the offer is cut to what can be.
        let verifiable = verifier.inner.supported_verify_schemes();
        let context = Context {
            extra: Arc::new(certificates_from(&intermediates.unwrap_or_default())),
            presented: Arc::new(Mutex::new(Vec::new())),
        };

        let mut config = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(verifier.clone())
            .with_no_client_auth();
        // Without a store each connection starts with an empty cache of its
        // own, which is to say it never resumes.
        if let Some(shared) = shared {
            config.resumption = Resumption::store(shared.tickets);
            config.client_auth_cert_resolver = shared.creds;
        }
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
        // The ClientHello was written above; its server's answer is checked
        // in `receive`, which puts this connection's context in place first.
        Ok(TlsClient { conn, verifier, context })
    }

    /// Whether this connection resumed an earlier session rather than doing
    /// a full handshake. Meaningful once the handshake is done.
    pub fn resumed(&self) -> bool {
        matches!(self.conn.handshake_kind(), Some(rustls::HandshakeKind::Resumed))
    }

    /// Hands over bytes that arrived from the network and returns how many were
    /// taken. One call does not always consume the whole slice, so the caller
    /// must loop from the returned offset or it will silently drop data.
    pub fn receive(&mut self, data: &[u8]) -> Result<usize, JsValue> {
        let taken = self
            .conn
            .read_tls(&mut Cursor::new(data))
            .map_err(|error| fail("TLS read failed", error))?;
        self.verifier.enter(&self.context);
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
        if let Ok(presented) = self.context.presented.lock() {
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
