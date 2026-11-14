"""Independent OpenSSL certificate fixtures and mutually authenticated TLS peers."""

import datetime
import json
import os
import socket
import ssl
import sys
import tempfile
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def cert_for(key, issuer_key, issuer, name, algorithm, ca=False):
    now = datetime.datetime.now(datetime.timezone.utc)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer.subject if issuer is not None else subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(hours=1))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=not ca,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=ca,
                crl_sign=ca,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
        .add_extension(
            x509.ExtendedKeyUsage(
                [ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]
            ),
            critical=False,
        )
        .sign(issuer_key, algorithm)
    )


def tlv(tag, body):
    size = len(body)
    if size < 128:
        length = bytes([size])
    else:
        count = (size.bit_length() + 7) // 8
        length = bytes([0x80 | count]) + size.to_bytes(count, "big")
    return bytes([tag]) + length + body


def children(sequence):
    def end_of(data, start):
        count = data[start + 1]
        header = start + 2
        if count & 0x80:
            count &= 0x7F
            length = int.from_bytes(data[header:header + count], "big")
            header += count
        else:
            length = count
        return header, header + length

    start, end = end_of(sequence, 0)
    assert sequence[0] == 0x30 and end == len(sequence)
    result = []
    while start < end:
        _, next_offset = end_of(sequence, start)
        result.append(sequence[start:next_offset])
        start = next_offset
    assert start == end
    return result


def omit_rsa_signature_null(cert, issuer_key, algorithm):
    outer = children(cert.public_bytes(serialization.Encoding.DER))
    tbs = children(outer[0])
    signature_algorithm = children(outer[1])
    assert signature_algorithm[-1] == b"\x05\x00"
    without_null = tlv(0x30, b"".join(signature_algorithm[:-1]))
    assert tbs[0][0] == 0xA0 and tbs[2] == outer[1]
    tbs[2] = without_null
    encoded_tbs = tlv(0x30, b"".join(tbs))
    signature = issuer_key.sign(encoded_tbs, padding.PKCS1v15(), algorithm)
    return x509.load_der_x509_certificate(
        tlv(0x30, encoded_tbs + without_null + tlv(3, b"\x00" + signature))
    )


def fixture(name, key, root, chain):
    return {
        "name": name,
        "root": root.public_bytes(serialization.Encoding.DER).hex(),
        "root_pem": root.public_bytes(serialization.Encoding.PEM).decode(),
        "chain": [cert.public_bytes(serialization.Encoding.DER).hex() for cert in chain],
        "chain_pem": b"".join(
            cert.public_bytes(serialization.Encoding.PEM) for cert in chain
        ).decode(),
        "key": key.private_bytes(
            serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).hex(),
        "traditional_key": key.private_bytes(
            serialization.Encoding.DER, serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ).hex(),
        "key_pem": key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode(),
    }


def fixtures():
    p256 = ec.generate_private_key(ec.SECP256R1())
    p384 = ec.generate_private_key(ec.SECP384R1())
    rsa2048 = rsa.generate_private_key(65537, 2048)
    rsa3072 = rsa.generate_private_key(65537, 3072)
    result = []
    for name, key, issuer_key, algorithm in [
        ("p384", p384, p256, hashes.SHA384()),
        ("p256", p256, p384, hashes.SHA256()),
        ("rsa2048", rsa2048, p256, hashes.SHA256()),
        ("rsa3072", rsa3072, p384, hashes.SHA384()),
    ]:
        root = cert_for(issuer_key, issuer_key, None, name + " root", algorithm, ca=True)
        leaf = cert_for(key, issuer_key, root, "localhost", algorithm)
        result.append(fixture(name, key, root, [leaf]))
    root = cert_for(rsa3072, rsa3072, None, "RSA root", hashes.SHA384(), ca=True)
    for algorithm in [hashes.SHA256(), hashes.SHA384(), hashes.SHA512()]:
        leaf = cert_for(p384, rsa3072, root, "localhost", algorithm)
        result.append(fixture("rsa-issuer-" + algorithm.name, p384, root, [leaf]))
        absent = omit_rsa_signature_null(leaf, rsa3072, algorithm)
        result.append(fixture("rsa-absent-" + algorithm.name, p384, root, [absent]))
    ec_root = cert_for(p384, p384, None, "EC root", hashes.SHA384(), ca=True)
    intermediate = cert_for(rsa2048, p384, ec_root, "RSA intermediate", hashes.SHA384(), ca=True)
    leaf = cert_for(p384, rsa2048, intermediate, "localhost", hashes.SHA384())
    result.append(fixture("intermediate", p384, ec_root, [leaf, intermediate]))
    ed_key = ed25519.Ed25519PrivateKey.generate().private_bytes(
        serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    return {"cases": result, "ed25519_key": ed_key.hex()}


def recv_exact(connection, length):
    result = bytearray()
    while len(result) < length:
        chunk = connection.recv(length - len(result))
        if not chunk:
            raise RuntimeError("TLS peer closed before the expected record")
        result.extend(chunk)
    return bytes(result)


def peer(mode):
    data = json.load(sys.stdin)
    case = data["case"]
    with tempfile.TemporaryDirectory(prefix="symcrypt-tls-") as directory:
        certificate = Path(directory) / "certificate.pem"
        private_key = Path(directory) / "private.pem"
        certificate.write_text(case["chain_pem"])
        descriptor = os.open(private_key, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w") as output:
            output.write(case["key_pem"])
        context = ssl.SSLContext(
            ssl.PROTOCOL_TLS_SERVER if mode == "server" else ssl.PROTOCOL_TLS_CLIENT
        )
        context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_verify_locations(cadata=case["root_pem"])
        context.load_cert_chain(certificate, private_key)
        context.set_ecdh_curve("secp384r1")
        if mode == "server":
            with socket.socket() as listener:
                listener.bind(("127.0.0.1", 0))
                listener.listen(1)
                listener.settimeout(15)
                print(listener.getsockname()[1], flush=True)
                connection, _ = listener.accept()
        else:
            connection = socket.create_connection(("127.0.0.1", data["port"]), timeout=15)
        with connection:
            connection.settimeout(15)
            with context.wrap_socket(
                connection, server_side=mode == "server",
                server_hostname="localhost" if mode == "client" else None,
            ) as secure:
                assert secure.version() == "TLSv1.3"
                assert secure.cipher()[0] == "TLS_AES_256_GCM_SHA384"
                assert secure.getpeercert(binary_form=True) == bytes.fromhex(case["chain"][0])
                if mode == "client":
                    secure.sendall(b"request" * 4096)
                    assert recv_exact(secure, 32768) == b"response" * 4096
                else:
                    assert recv_exact(secure, 28672) == b"request" * 4096
                    secure.sendall(b"response" * 4096)
                secure.unwrap().close()
        print("ok", flush=True)


if sys.argv[1] == "fixtures":
    print(json.dumps(fixtures()))
else:
    peer(sys.argv[1])
