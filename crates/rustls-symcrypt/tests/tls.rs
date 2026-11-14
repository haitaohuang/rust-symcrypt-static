#![cfg(feature = "std")]

use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer, ServerName},
    server::WebPkiClientVerifier,
    ClientConfig, ClientConnection, Connection, Error, ProtocolVersion, RootCertStore,
    ServerConfig, ServerConnection, SignatureScheme, StreamOwned,
};
use serde_json::{json, Value};
use std::{
    io::{BufRead, BufReader, Cursor, Read, Write},
    net::{TcpListener, TcpStream},
    process::{Child, Command, Output, Stdio},
    sync::{Arc, OnceLock},
    time::{Duration, Instant},
};

fn unhex(value: &Value) -> Vec<u8> {
    let text = value.as_str().unwrap();
    assert_eq!(text.len() % 2, 0);
    text.as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn fixtures() -> &'static Value {
    static FIXTURES: OnceLock<Value> = OnceLock::new();
    FIXTURES.get_or_init(|| {
        let output = Command::new("python3")
            .args(["-c", include_str!("tls_reference.py"), "fixtures"])
            .output()
            .expect("Python 3 is required for TLS interoperability tests");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice(&output.stdout).unwrap()
    })
}

fn chain(case: &Value) -> Vec<CertificateDer<'static>> {
    case["chain"]
        .as_array()
        .unwrap()
        .iter()
        .map(|cert| CertificateDer::from(unhex(cert)))
        .collect()
}

fn private_key(case: &Value, field: &str) -> PrivateKeyDer<'static> {
    PrivateKeyDer::try_from(unhex(&case[field])).unwrap()
}

fn configs(case: &Value, key_field: &str) -> (Arc<ClientConfig>, Arc<ServerConfig>) {
    let provider = Arc::new(rustls_symcrypt::provider().unwrap());
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(unhex(&case["root"])))
        .unwrap();
    let verifier =
        WebPkiClientVerifier::builder_with_provider(Arc::new(roots.clone()), provider.clone())
            .build()
            .unwrap();
    let server = ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_client_cert_verifier(verifier)
        .with_single_cert(chain(case), private_key(case, key_field))
        .unwrap();
    let client = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_client_auth_cert(chain(case), private_key(case, key_field))
        .unwrap();
    (Arc::new(client), Arc::new(server))
}

fn transfer(from: &mut Connection, to: &mut Connection) -> Result<bool, Error> {
    if !from.wants_write() {
        return Ok(false);
    }
    let mut bytes = Vec::new();
    while from.wants_write() {
        assert!(from.write_tls(&mut bytes).unwrap() > 0);
    }
    let mut input = Cursor::new(bytes);
    while input.position() < input.get_ref().len() as u64 {
        assert!(to.read_tls(&mut input).unwrap() > 0);
        to.process_new_packets()?;
    }
    Ok(true)
}

fn exchange(client: &mut Connection, server: &mut Connection) -> Result<(), Error> {
    for _ in 0..64 {
        let sent = transfer(client, server)?;
        let received = transfer(server, client)?;
        if !sent && !received {
            return Ok(());
        }
    }
    panic!("TLS exchange made no bounded progress");
}

fn pair(
    client: Arc<ClientConfig>,
    server: Arc<ServerConfig>,
    name: &str,
) -> (Connection, Connection) {
    (
        Connection::Client(
            ClientConnection::new(client, ServerName::try_from(name.to_owned()).unwrap()).unwrap(),
        ),
        Connection::Server(ServerConnection::new(server).unwrap()),
    )
}

#[test]
#[ignore = "requires Python 3 and cryptography; exercised explicitly in CI"]
fn mutually_authenticated_tls_validates_ec_rsa_and_parameter_compatibility() {
    for case in fixtures()["cases"].as_array().unwrap() {
        for key_field in ["key", "traditional_key"] {
            let (client_config, server_config) = configs(case, key_field);
            let (mut client, mut server) = pair(client_config, server_config, "localhost");
            exchange(&mut client, &mut server)
                .unwrap_or_else(|error| panic!("{}: {error}", case["name"]));
            assert!(!client.is_handshaking() && !server.is_handshaking());
            assert_eq!(client.protocol_version(), Some(ProtocolVersion::TLSv1_3));
            assert_eq!(client.peer_certificates().unwrap(), chain(case));
            assert_eq!(server.peer_certificates().unwrap(), chain(case));
            let context = Some(b"channel binding".as_slice());
            assert_eq!(
                client
                    .export_keying_material([0; 48], b"test exporter", context)
                    .unwrap(),
                server
                    .export_keying_material([0; 48], b"test exporter", context)
                    .unwrap(),
            );
            let request = vec![0x42; 30000];
            client.writer().write_all(&request).unwrap();
            exchange(&mut client, &mut server).unwrap();
            let mut received = vec![0; request.len()];
            server.reader().read_exact(&mut received).unwrap();
            assert_eq!(received, request);
            server.refresh_traffic_keys().unwrap();
            server.writer().write_all(b"after key update").unwrap();
            exchange(&mut client, &mut server).unwrap();
            let mut response = [0; 16];
            client.reader().read_exact(&mut response).unwrap();
            assert_eq!(&response, b"after key update");
        }
    }
}

#[test]
#[ignore = "requires Python 3 and cryptography; exercised explicitly in CI"]
fn tls_does_not_bypass_names_trust_signatures_or_key_matching() {
    let cases = fixtures()["cases"].as_array().unwrap();
    let (client, server) = configs(&cases[0], "key");
    let (mut c, mut s) = pair(client.clone(), server.clone(), "wrong.example");
    assert!(matches!(
        exchange(&mut c, &mut s),
        Err(Error::InvalidCertificate(_))
    ));
    let (unrelated_client, _) = configs(&cases[1], "key");
    let (mut c, mut s) = pair(unrelated_client, server.clone(), "localhost");
    assert!(matches!(
        exchange(&mut c, &mut s),
        Err(Error::InvalidCertificate(_))
    ));

    let mut corrupted = cases[0].clone();
    let mut leaf = unhex(&corrupted["chain"][0]);
    *leaf.last_mut().unwrap() ^= 1;
    corrupted["chain"][0] = Value::String(leaf.iter().map(|byte| format!("{byte:02x}")).collect());
    let (_, bad_server) = configs(&corrupted, "key");
    let (mut c, mut s) = pair(client, bad_server, "localhost");
    assert!(matches!(
        exchange(&mut c, &mut s),
        Err(Error::InvalidCertificate(_))
    ));

    let provider = rustls_symcrypt::provider().unwrap();
    assert!(!provider
        .signature_verification_algorithms
        .supported_schemes()
        .contains(&SignatureScheme::ED25519));
    assert!(provider
        .key_provider
        .load_private_key(PrivateKeyDer::try_from(unhex(&fixtures()["ed25519_key"])).unwrap(),)
        .is_err());
    assert!(ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(chain(&cases[0]), private_key(&cases[1], "key"))
        .is_err());
}

struct Peer(Option<Child>);

impl Peer {
    fn start(mode: &str, input: &Value) -> Self {
        let mut child = Command::new("python3")
            .args(["-c", include_str!("tls_reference.py"), mode])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("Python 3 is required for TLS interoperability tests");
        child
            .stdin
            .take()
            .unwrap()
            .write_all(&serde_json::to_vec(input).unwrap())
            .unwrap();
        Self(Some(child))
    }

    fn finish(mut self) -> Output {
        let output = self.0.take().unwrap().wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "OpenSSL peer failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output
    }
}

impl Drop for Peer {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn timeouts(socket: &TcpStream) {
    socket
        .set_read_timeout(Some(Duration::from_secs(15)))
        .unwrap();
    socket
        .set_write_timeout(Some(Duration::from_secs(15)))
        .unwrap();
}

#[test]
#[ignore = "requires Python 3/OpenSSL/cryptography and loopback sockets; exercised explicitly in CI"]
fn native_tls_interoperates_with_openssl_in_both_roles() {
    for case in &fixtures()["cases"].as_array().unwrap()[..4] {
        let (client, server) = configs(case, "key");
        let mut peer = Peer::start("server", &json!({"case": case}));
        let mut output = BufReader::new(peer.0.as_mut().unwrap().stdout.take().unwrap());
        let mut port = String::new();
        output.read_line(&mut port).unwrap();
        let socket =
            TcpStream::connect(("127.0.0.1", port.trim().parse::<u16>().unwrap())).unwrap();
        timeouts(&socket);
        let client =
            ClientConnection::new(client, ServerName::try_from("localhost").unwrap()).unwrap();
        let mut secure = StreamOwned::new(client, socket);
        secure.write_all(&b"request".repeat(4096)).unwrap();
        let mut response = vec![0; 32768];
        secure.read_exact(&mut response).unwrap();
        assert_eq!(response, b"response".repeat(4096));
        secure.conn.send_close_notify();
        secure.flush().unwrap();
        let mut eof = [0];
        assert_eq!(secure.read(&mut eof).unwrap(), 0);
        assert!(secure
            .conn
            .peer_certificates()
            .unwrap()
            .starts_with(&chain(case)));
        peer.finish();

        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let peer = Peer::start(
            "client",
            &json!({"case": case, "port": listener.local_addr().unwrap().port()}),
        );
        let deadline = Instant::now() + Duration::from_secs(15);
        let socket = loop {
            match listener.accept() {
                Ok((socket, _)) => break socket,
                Err(error)
                    if error.kind() == std::io::ErrorKind::WouldBlock
                        && Instant::now() < deadline =>
                {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(error) => panic!("OpenSSL peer did not connect: {error}"),
            }
        };
        timeouts(&socket);
        let mut secure = StreamOwned::new(ServerConnection::new(server).unwrap(), socket);
        let mut request = vec![0; 28672];
        secure.read_exact(&mut request).unwrap();
        assert_eq!(request, b"request".repeat(4096));
        secure.write_all(&b"response".repeat(4096)).unwrap();
        secure.conn.send_close_notify();
        secure.flush().unwrap();
        assert_eq!(secure.read(&mut eof).unwrap(), 0);
        assert!(secure
            .conn
            .peer_certificates()
            .unwrap()
            .starts_with(&chain(case)));
        peer.finish();
    }
}
