"""Ephemeral SPDM certificate fixtures, independently signed by OpenSSL."""
import datetime
import json

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.x509.oid import NameOID, ObjectIdentifier

NOW = datetime.datetime(2025, 1, 1, tzinfo=datetime.timezone.utc)
ROOT_NAME = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "SPDM test root")])
LEAF_NAME = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "SPDM test identity")])
RESPONDER = ObjectIdentifier("1.3.6.1.4.1.412.274.3")
REQUESTER = ObjectIdentifier("1.3.6.1.4.1.412.274.4")
root_key = ec.generate_private_key(ec.SECP384R1())
leaf_key = ec.generate_private_key(ec.SECP384R1())


def certificate(subject, key, ca, eku=None):
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject).issuer_name(ROOT_NAME)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(NOW - datetime.timedelta(days=30))
        .not_valid_after(NOW + datetime.timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=ca,
            crl_sign=ca, encipher_only=None, decipher_only=None,
        ), critical=True)
    )
    if eku is not None:
        builder = builder.add_extension(x509.ExtendedKeyUsage(eku), critical=False)
    return builder.sign(root_key, hashes.SHA384()).public_bytes(serialization.Encoding.DER)


root = certificate(ROOT_NAME, root_key, True)
r, s = decode_dss_signature(leaf_key.sign(b"message", ec.ECDSA(hashes.SHA384())))
signature = (r.to_bytes(48, "big") + s.to_bytes(48, "big")).hex()
chains = []
for eku, valid in [
    (None, True), ([RESPONDER], True), ([REQUESTER], False),
    ([REQUESTER, RESPONDER], True), ([ObjectIdentifier("1.3.6.1.5.5.7.3.1")], True),
]:
    chains.append({
        "chain": (root + certificate(LEAF_NAME, leaf_key, False, eku)).hex(),
        "signature": signature, "valid": valid,
    })
print(json.dumps({"now": int(NOW.timestamp()), "chains": chains}))
