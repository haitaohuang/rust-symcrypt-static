"""Independent OpenSSL-backed reference; keys exist only for this local test run."""
import json
import math
import sys

from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

MESSAGE = b"interop message"
HASHES = {"sha256": hashes.SHA256, "sha384": hashes.SHA384, "sha512": hashes.SHA512}
DER = serialization.Encoding.DER
PKCS8 = serialization.PrivateFormat.PKCS8
SPKI = serialization.PublicFormat.SubjectPublicKeyInfo


def private_bytes(key):
    return key.private_bytes(DER, PKCS8, serialization.NoEncryption()).hex()


def public_bytes(key):
    return key.public_key().public_bytes(DER, SPKI).hex()


def mac(algorithm, key, message):
    context = hmac.HMAC(key, algorithm)
    context.update(message)
    return context.finalize()


def rsa_padding(mode, algorithm):
    if mode == "pkcs1":
        return padding.PKCS1v15()
    return padding.PSS(mgf=padding.MGF1(algorithm), salt_length=algorithm.digest_size)


def check(case):
    kind = case["kind"]
    if kind in ("ec", "rsa"):
        original = serialization.load_der_private_key(bytes.fromhex(case["private"]), None)
        assert public_bytes(original) == case["public"]
        algorithm = HASHES[case.get("hash", "sha384")]()
        if kind == "ec":
            original.public_key().verify(bytes.fromhex(case["signature"]), MESSAGE, ec.ECDSA(algorithm))
            peer = serialization.load_der_public_key(bytes.fromhex(case["peer"]))
            assert original.exchange(ec.ECDH(), peer).hex() == case["secret"]
            generated = ec.generate_private_key(original.curve)
            return {
                "private": private_bytes(generated),
                "public": public_bytes(generated),
                "signature": generated.sign(MESSAGE, ec.ECDSA(algorithm)).hex(),
                "secret": generated.exchange(ec.ECDH(), original.public_key()).hex(),
            }
        generated = rsa.generate_private_key(65537, case["bits"])
        signatures = []
        for item in case["signatures"]:
            algorithm = HASHES[item["hash"]]()
            mode = rsa_padding(item["padding"], algorithm)
            original.public_key().verify(bytes.fromhex(item["signature"]), MESSAGE, mode, algorithm)
            signatures.append({
                **item, "signature": generated.sign(MESSAGE, mode, algorithm).hex()
            })
        numbers = generated.private_numbers()
        period = math.lcm(numbers.p - 1, numbers.q - 1)
        alternate_d = numbers.d + period if numbers.d + period < numbers.public_numbers.n else numbers.d - period
        equivalent = rsa.RSAPrivateNumbers(
            numbers.p, numbers.q, alternate_d, numbers.dmp1, numbers.dmq1,
            numbers.iqmp, numbers.public_numbers
        ).private_key()
        return {
            "private": private_bytes(generated),
            "public": public_bytes(generated),
            "signatures": signatures,
            "equivalent_exponent": private_bytes(equivalent),
            "invalid_pss": [
                generated.sign(MESSAGE, padding.PSS(mgf=padding.MGF1(hashes.SHA384()), salt_length=0), hashes.SHA384()).hex(),
                generated.sign(MESSAGE, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=48), hashes.SHA384()).hex(),
            ],
        }
    if kind == "aead":
        cipher = (ChaCha20Poly1305 if case["algorithm"] == "chacha" else AESGCM)(bytes.fromhex(case["key"]))
        assert cipher.encrypt(bytes([8]) * 12, MESSAGE, b"header").hex() == case["ciphertext"]
        return {"ciphertext": cipher.encrypt(bytes([9]) * 12, MESSAGE, b"header").hex()}
    if kind == "kdf":
        algorithm = HASHES[case["hash"]]()
        assert mac(algorithm, b"key", MESSAGE).hex() == case["hmac"]
        prk = mac(algorithm, b"salt", b"input")
        assert prk.hex() == case["prk"]
        assert HKDFExpand(algorithm, 99, b"info").derive(prk).hex() == case["expanded"]
        return {"verified": True}
    raise ValueError("unknown test kind")


print(json.dumps([check(case) for case in json.load(sys.stdin)]))
