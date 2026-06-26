from __future__ import annotations

import base64
import json
from dataclasses import asdict, dataclass, is_dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


OAEP_SHA256 = padding.OAEP(
    mgf=padding.MGF1(algorithm=hashes.SHA256()),
    algorithm=hashes.SHA256(),
    label=None,
)

PSS_SHA256 = padding.PSS(
    mgf=padding.MGF1(hashes.SHA256()),
    salt_length=padding.PSS.MAX_LENGTH,
)


@dataclass(frozen=True)
class KeyPair:
    """Tiene insieme una chiave privata RSA e la sua chiave pubblica."""

    private_key: rsa.RSAPrivateKey
    public_key: rsa.RSAPublicKey


def generate_rsa_keypair(key_size: int = 2048) -> KeyPair:
    """Crea una nuova coppia di chiavi RSA per firme o cifratura."""

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    return KeyPair(private_key=private_key, public_key=private_key.public_key())


def public_key_to_pem(public_key: rsa.RSAPublicKey) -> str:
    """Converte una chiave pubblica RSA in testo PEM."""

    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")


def public_key_from_pem(pem: str) -> rsa.RSAPublicKey:
    """Ricostruisce una chiave pubblica RSA da una stringa PEM."""

    key = serialization.load_pem_public_key(pem.encode("ascii"))
    if not isinstance(key, rsa.RSAPublicKey):
        raise TypeError("expected an RSA public key")
    return key


def canonical_json(value: Any) -> bytes:
    """Serializza un valore in JSON stabile, adatto a firme e hash."""

    return json.dumps(_json_ready(value), sort_keys=True, separators=(",", ":")).encode("utf-8")


def b64encode(data: bytes) -> str:
    """Codifica byte in base64 URL-safe, come testo ASCII."""

    return base64.urlsafe_b64encode(data).decode("ascii")


def b64decode(data: str) -> bytes:
    """Decodifica testo base64 URL-safe in byte."""

    return base64.urlsafe_b64decode(data.encode("ascii"))


def sha256(data: bytes) -> bytes:
    """Calcola il digest SHA-256 in formato binario."""

    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    return digest.finalize()


def sha256_hex(data: bytes) -> str:
    """Calcola SHA-256 e lo restituisce come stringa esadecimale."""

    return sha256(data).hex()


def sign(private_key: rsa.RSAPrivateKey, message: bytes) -> str:
    """Firma un messaggio con RSA-PSS e restituisce la firma in base64."""

    signature = private_key.sign(message, PSS_SHA256, hashes.SHA256())
    return b64encode(signature)


def verify(public_key: rsa.RSAPublicKey, message: bytes, signature: str) -> bool:
    """Controlla una firma RSA-PSS senza propagare errori di firma."""

    try:
        public_key.verify(b64decode(signature), message, PSS_SHA256, hashes.SHA256())
        return True
    except InvalidSignature:
        return False


def encrypt_for(public_key: rsa.RSAPublicKey, plaintext: bytes) -> str:
    """Cifra byte per il possessore della chiave pubblica indicata."""

    return b64encode(public_key.encrypt(plaintext, OAEP_SHA256))


def decrypt_with(private_key: rsa.RSAPrivateKey, ciphertext: str) -> bytes:
    """Decifra un testo cifrato base64 con la chiave privata RSA."""

    return private_key.decrypt(b64decode(ciphertext), OAEP_SHA256)


def _json_ready(value: Any) -> Any:
    """Trasforma dataclass e byte in valori semplici serializzabili in JSON."""

    if is_dataclass(value):
        return _json_ready(asdict(value))
    if isinstance(value, bytes):
        return b64encode(value)
    if isinstance(value, dict):
        return {str(k): _json_ready(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_ready(item) for item in value]
    return value
