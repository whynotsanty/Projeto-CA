"""Cryptographic helpers for the FedFernet prototype."""

from __future__ import annotations

import secrets

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.hashes import SHA256


def generate_rsa_key_pair(key_size: int = 2048) -> tuple[bytes, bytes]:
    """Return an RSA private/public key pair serialized as PEM bytes."""
    if key_size < 2048:
        raise ValueError("RSA keys must have at least 2048 bits")

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem, public_pem


def generate_aes_key() -> bytes:
    """Return a fresh 256-bit AES key."""
    return secrets.token_bytes(32)


def load_private_key(private_pem: bytes) -> rsa.RSAPrivateKey:
    """Load an unencrypted PEM-encoded RSA private key."""
    key = serialization.load_pem_private_key(private_pem, password=None)
    if not isinstance(key, rsa.RSAPrivateKey):
        raise TypeError("Expected an RSA private key")
    return key


def load_public_key(public_pem: bytes) -> rsa.RSAPublicKey:
    """Load a PEM-encoded RSA public key."""
    key = serialization.load_pem_public_key(public_pem)
    if not isinstance(key, rsa.RSAPublicKey):
        raise TypeError("Expected an RSA public key")
    return key


def sign(private_key: rsa.RSAPrivateKey, data: bytes) -> bytes:
    """Sign data with RSA-PSS and SHA-256."""
    return private_key.sign(
        data,
        padding.PSS(mgf=padding.MGF1(SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        SHA256(),
    )


def verify(public_key: rsa.RSAPublicKey, signature: bytes, data: bytes) -> None:
    """Verify an RSA-PSS signature or raise ``InvalidSignature``."""
    public_key.verify(
        signature,
        data,
        padding.PSS(mgf=padding.MGF1(SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        SHA256(),
    )