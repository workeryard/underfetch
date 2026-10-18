//! TLS for a socket the Workers runtime will not encrypt for us.
//!
//! `startTls({ expectedServerHostname })` is the obvious way to secure a
//! tunnelled connection, but workerd logs that option as unsupported and has an
//! autogate ready to reject it outright, so a proxied request cannot rely on
//! it. This crate puts rustls behind a small state machine instead: JavaScript
//! owns the socket and pumps bytes through, and nothing here does any I/O.

mod pq;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::{
    ResolvesClientCert, ClientSessionStore, Resumption, Tls12ClientSessionValue,
    Tls13ClientSessionValue, WebPkiServerVerifier,
};
use rustls::fingerprint::Fingerprint;
use rustls::sign::CertifiedKey;
use rustls::{
    CipherSuite, ClientConfig, ClientConnection, DigitallySignedStruct, DistinguishedName, Error,
    NamedGroup, RootCertStore, SignatureScheme,
};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use std::cell::{Cell, RefCell};
use std::collections::{HashMap, VecDeque};
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

/// Certificates given by the caller, as `(length u32, bytes)` records each
/// holding one DER certificate or any number in PEM.
fn certificates_given(blob: &[u8]) -> Result<Vec<CertificateDer<'static>>, JsValue> {
    let mut out = Vec::new();
    for record in certificates_from(blob) {
        // An empty string is no certificate, not a broken one.
        if record.is_empty() {
            continue;
        }
        if record.starts_with(b"-----BEGIN") {
            for cert in CertificateDer::pem_slice_iter(&record) {
                out.push(cert.map_err(|error| fail("could not read a PEM certificate", error))?);
            }
        } else {
            out.push(record);
        }
    }
    Ok(out)
}

/// A private key in PEM, or in DER as PKCS#8, PKCS#1 or SEC1.
fn private_key(blob: &[u8]) -> Result<PrivateKeyDer<'static>, JsValue> {
    if blob.starts_with(b"-----BEGIN") {
        return PrivateKeyDer::from_pem_slice(blob)
            .map_err(|error| fail("could not read the PEM private key", error));
    }
    PrivateKeyDer::try_from(blob.to_vec()).map_err(|error| fail("could not read the private key", error))
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
///
/// It trusts the web PKI's roots, or only the ones a caller gives instead;
/// and told not to verify, it accepts any certificate, though the handshake
/// must still be signed by the key of the one presented, as `curl -k` has it.
#[derive(Debug)]
struct Completing {
    inner: Arc<WebPkiServerVerifier>,
    current: Mutex<Context>,
    verify: bool,
}

/// One connection's share of the verifier: the intermediates fetched for it,
/// and where to record the chain its server presents.
#[derive(Debug, Clone, Default)]
struct Context {
    extra: Arc<Vec<CertificateDer<'static>>>,
    presented: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl Completing {
    fn new(ca: &[CertificateDer<'static>], verify: bool) -> Result<Completing, JsValue> {
        let mut roots = RootCertStore::empty();
        // Not verifying still needs a root store to build the signature
        // checks on, and an empty one is refused.
        if ca.is_empty() {
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        }
        for cert in ca {
            roots
                .add(cert.clone())
                .map_err(|error| fail("a CA certificate could not be trusted", error))?;
        }
        let inner = WebPkiServerVerifier::builder_with_provider(
            Arc::new(roots),
            Arc::new(rustls::crypto::ring::default_provider()),
        )
        .build()
        .map_err(|error| fail("could not build the certificate verifier", error))?;
        Ok(Completing { inner, current: Mutex::new(Context::default()), verify })
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
        if !self.verify {
            return Ok(ServerCertVerified::assertion());
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
    /// A store for one session's connections, which also says whom they
    /// trust and who they are — rustls resumes a ticket only under the
    /// verifier and client certificate that earned it. `ca` replaces the web
    /// PKI's roots, as `(length u32, DER or PEM)` records; `verify: false`
    /// accepts any server certificate; `client_chain` and `client_key` are
    /// presented when a server asks for a certificate.
    #[wasm_bindgen(constructor)]
    pub fn new(
        ca: Option<Vec<u8>>,
        verify: Option<bool>,
        client_chain: Option<Vec<u8>>,
        client_key: Option<Vec<u8>>,
    ) -> Result<TicketStore, JsValue> {
        let ca = certificates_given(&ca.unwrap_or_default())?;
        let creds: Arc<dyn ResolvesClientCert> = match (client_chain, client_key) {
            (Some(chain), Some(key)) => Arc::new(ClientCert::new(&chain, &key)?),
            (None, None) => Arc::new(NoClientCert),
            _ => return Err(JsValue::from_str("a client certificate needs its key, and a key its certificate")),
        };
        let verifier = Arc::new(Completing::new(&ca, verify.unwrap_or(true))?);
        let id = NEXT_ID.with(|next| {
            let id = next.get();
            next.set(id.wrapping_add(1).max(1));
            id
        });
        let shared = Shared {
            // As many hosts as rustls' own default cache holds.
            tickets: Arc::new(TicketsOnly::default()),
            verifier,
            creds,
        };
        STORES.with(|stores| stores.borrow_mut().insert(id, shared));
        Ok(TicketStore { id })
    }

    #[wasm_bindgen(getter)]
    pub fn id(&self) -> u32 {
        self.id
    }

    /// Every TLS 1.3 ticket held, as bytes a later `import` takes back —
    /// in another isolate, or after a deploy. Nothing is used up. TLS 1.2
    /// sessions are not kept: they are rare now and their state is larger.
    ///
    /// These bytes resume sessions: keep them as a password is kept.
    pub fn export(&self) -> Vec<u8> {
        let mut out = vec![EXPORT_FORMAT];
        let Some(shared) = self.shared() else {
            return out;
        };
        let Ok(tickets) = shared.tickets.tls13.lock() else {
            return out;
        };
        let mut records: Vec<(String, Vec<u8>)> = Vec::new();
        for name in &tickets.order {
            for value in tickets.by_host.get(name).into_iter().flatten() {
                records.push((name.to_str().into_owned(), value.to_bytes()));
            }
        }
        out.extend((records.len() as u32).to_be_bytes());
        for (host, ticket) in records {
            out.extend((host.len() as u16).to_be_bytes());
            out.extend(host.as_bytes());
            out.extend((ticket.len() as u32).to_be_bytes());
            out.extend(ticket);
        }
        out
    }

    /// Takes back what `export` wrote, and answers how many tickets were
    /// usable. A ticket for a suite this build lacks is skipped; bytes of
    /// another layout are refused whole.
    pub fn import(&self, blob: &[u8]) -> Result<u32, JsValue> {
        let bad = || JsValue::from_str("these are not tickets this build exported");
        let shared = self.shared().ok_or_else(bad)?;
        if blob.first() != Some(&EXPORT_FORMAT) {
            return Err(bad());
        }
        let mut at = 1;
        let mut take = |n: usize| -> Result<&[u8], JsValue> {
            let slice = blob.get(at..at + n).ok_or_else(bad)?;
            at += n;
            Ok(slice)
        };
        let count = u32::from_be_bytes(take(4)?.try_into().map_err(|_| bad())?);
        let suites = rustls::crypto::ring::default_provider().cipher_suites;
        let verifier: Arc<dyn ServerCertVerifier> = shared.verifier.clone();
        let mut usable = 0;
        let mut parsed = Vec::new();
        for _ in 0..count {
            let host_len = u16::from_be_bytes(take(2)?.try_into().map_err(|_| bad())?) as usize;
            let host = std::str::from_utf8(take(host_len)?).map_err(|_| bad())?.to_string();
            let len = u32::from_be_bytes(take(4)?.try_into().map_err(|_| bad())?) as usize;
            parsed.push((host, take(len)?.to_vec()));
        }
        if at != blob.len() {
            return Err(bad());
        }
        let Ok(mut tickets) = shared.tickets.tls13.lock() else {
            return Err(bad());
        };
        for (host, bytes) in parsed {
            let Ok(name) = ServerName::try_from(host) else {
                continue;
            };
            if let Some(value) =
                Tls13ClientSessionValue::from_bytes(&bytes, &suites, &verifier, &shared.creds)
            {
                tickets.insert(name, value);
                usable += 1;
            }
        }
        Ok(usable)
    }
}

impl TicketStore {
    fn shared(&self) -> Option<Shared> {
        STORES.with(|stores| stores.borrow().get(&self.id).cloned())
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

/// The certificate a session presents when a server asks for one, for mutual
/// TLS. Its key signs with whatever scheme ring supports for it: RSA, ECDSA
/// on P-256 or P-384, or Ed25519.
#[derive(Debug)]
struct ClientCert(Arc<CertifiedKey>);

impl ClientCert {
    fn new(chain: &[u8], key: &[u8]) -> Result<ClientCert, JsValue> {
        let chain = certificates_given(chain)?;
        if chain.is_empty() {
            return Err(JsValue::from_str("the client certificate chain is empty"));
        }
        let key = rustls::crypto::ring::default_provider()
            .key_provider
            .load_private_key(private_key(key)?)
            .map_err(|error| fail("the client key cannot sign", error))?;
        Ok(ClientCert(Arc::new(CertifiedKey::new(chain, key))))
    }
}

impl ResolvesClientCert for ClientCert {
    fn resolve(&self, _: &[&[u8]], schemes: &[SignatureScheme]) -> Option<Arc<CertifiedKey>> {
        // Only when the key can sign with a scheme the server offered.
        self.0.key.choose_scheme(schemes)?;
        Some(self.0.clone())
    }

    fn has_certs(&self) -> bool {
        true
    }
}

/// At most this many hosts, and this many tickets for each: the bounds
/// rustls' own in-memory cache uses.
const MAX_HOSTS: usize = 256;
const TICKETS_PER_HOST: usize = 8;

/// The layout of `TicketStore::export`, bumped on any change so bytes from
/// another build are refused rather than misread.
const EXPORT_FORMAT: u8 = 1;

/// Our own store rather than rustls' `ClientSessionMemoryCache`, whose
/// contents cannot be read back out: a store that can be saved has to be
/// able to list what it holds.
#[derive(Debug, Default)]
struct TicketsOnly {
    tls13: Mutex<Tickets>,
    tls12: Mutex<HashMap<ServerName<'static>, Tls12ClientSessionValue>>,
}

#[derive(Debug, Default)]
struct Tickets {
    by_host: HashMap<ServerName<'static>, VecDeque<Tls13ClientSessionValue>>,
    /// Hosts in the order they were first seen, oldest first, for eviction.
    order: VecDeque<ServerName<'static>>,
}

impl Tickets {
    fn insert(&mut self, name: ServerName<'static>, value: Tls13ClientSessionValue) {
        if !self.by_host.contains_key(&name) {
            if self.order.len() >= MAX_HOSTS {
                if let Some(oldest) = self.order.pop_front() {
                    self.by_host.remove(&oldest);
                }
            }
            self.order.push_back(name.clone());
        }
        let held = self.by_host.entry(name).or_default();
        held.push_back(value);
        if held.len() > TICKETS_PER_HOST {
            held.pop_front();
        }
    }
}

impl ClientSessionStore for TicketsOnly {
    fn set_kx_hint(&self, _: ServerName<'static>, _: NamedGroup) {}

    fn kx_hint(&self, _: &ServerName<'_>) -> Option<NamedGroup> {
        None
    }

    fn set_tls12_session(&self, name: ServerName<'static>, value: Tls12ClientSessionValue) {
        if let Ok(mut held) = self.tls12.lock() {
            if held.len() >= MAX_HOSTS && !held.contains_key(&name) {
                if let Some(any) = held.keys().next().cloned() {
                    held.remove(&any);
                }
            }
            held.insert(name, value);
        }
    }

    fn tls12_session(&self, name: &ServerName<'_>) -> Option<Tls12ClientSessionValue> {
        self.tls12.lock().ok()?.get(name).cloned()
    }

    fn remove_tls12_session(&self, name: &ServerName<'static>) {
        if let Ok(mut held) = self.tls12.lock() {
            held.remove(name);
        }
    }

    fn insert_tls13_ticket(&self, name: ServerName<'static>, value: Tls13ClientSessionValue) {
        if let Ok(mut tickets) = self.tls13.lock() {
            tickets.insert(name, value);
        }
    }

    /// The newest first, and each at most once, as the trait requires.
    fn take_tls13_ticket(&self, name: &ServerName<'static>) -> Option<Tls13ClientSessionValue> {
        self.tls13.lock().ok()?.by_host.get_mut(name)?.pop_back()
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
        key_shares: Option<Vec<u16>>,
        resume: Option<bool>,
    ) -> Result<TlsClient, JsValue> {
        let shared = tickets.and_then(|id| STORES.with(|stores| stores.borrow().get(&id).cloned()));
        let verifier = match &shared {
            Some(shared) => shared.verifier.clone(),
            None => Arc::new(Completing::new(&[], true)?),
        };
        // The schemes this verifier can check. A browser offers more — SHA-1,
        // and ECDSA with SHA-512 — and an old TLS 1.2 server that picks one
        // cannot be verified. Asked for, the offer is cut to what can be.
        let verifiable = verifier.inner.supported_verify_schemes();
        let context = Context {
            extra: Arc::new(certificates_from(&intermediates.unwrap_or_default())),
            presented: Arc::new(Mutex::new(Vec::new())),
        };

        // A browser that leads with X25519MLKEM768 gets it, first, so rustls
        // makes it the key share and sends plain X25519 beside it. Only a
        // profile naming the group asks for it: the rest keep rustls' own.
        let post_quantum = named_groups
            .as_ref()
            .is_some_and(|groups| groups.contains(&u16::from(NamedGroup::X25519MLKEM768)));
        // The key shares the browser sent, where its capture says: a P-256 one
        // after X25519, as Firefox sends, needs the group that makes three.
        let p256_share = key_shares
            .as_ref()
            .is_some_and(|shares| shares.contains(&u16::from(NamedGroup::secp256r1)));
        let mut provider = rustls::crypto::ring::default_provider();
        let lead = match (post_quantum, p256_share) {
            (true, true) => Some(pq::X25519MLKEM768_THEN_P256),
            (true, false) => Some(pq::X25519MLKEM768),
            (false, true) => Some(pq::X25519_THEN_P256),
            (false, false) => None,
        };
        if let Some(lead) = lead {
            provider.kx_groups.insert(0, lead);
        }
        let mut config = ClientConfig::builder_with_provider(Arc::new(provider))
            .with_safe_default_protocol_versions()
            .map_err(|error| fail("could not configure TLS", error))?
            .dangerous()
            .with_custom_certificate_verifier(verifier.clone())
            .with_no_client_auth();
        // Without a store each connection starts with an empty cache of its
        // own, which is to say it never resumes; nor does one told not to,
        // which still takes the store's trust and client certificate.
        if let Some(shared) = shared {
            if resume.unwrap_or(true) {
                config.resumption = Resumption::store(shared.tickets);
            }
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

    /// The key exchange group the handshake settled on, as its TLS number —
    /// 0x11ec for X25519MLKEM768, 0x001d for X25519. Meaningful once the
    /// handshake is done.
    #[wasm_bindgen(js_name = keyExchangeGroup)]
    pub fn key_exchange_group(&self) -> Option<u16> {
        self.conn
            .negotiated_key_exchange_group()
            .map(|group| u16::from(group.name()))
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
