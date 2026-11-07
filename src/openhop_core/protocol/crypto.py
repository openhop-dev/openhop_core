import hashlib
import hmac

from Crypto.Cipher import AES
from nacl.bindings import (
    crypto_scalarmult,
    crypto_scalarmult_base,
    crypto_scalarmult_ed25519_base_noclamp,
    crypto_sign_ed25519_pk_to_curve25519,
    crypto_sign_ed25519_sk_to_curve25519,
)

from .constants import CIPHER_BLOCK_SIZE, CIPHER_MAC_SIZE


class CryptoUtils:
    @staticmethod
    def sha256(data: bytes) -> bytes:
        return hashlib.sha256(data).digest()

    @staticmethod
    def _hmac_sha256(key: bytes, data: bytes) -> bytes:
        return hmac.new(key, data, hashlib.sha256).digest()

    @staticmethod
    def _aes_encrypt(key: bytes, data: bytes) -> bytes:
        cipher = AES.new(key, AES.MODE_ECB)

        # Pad to match decryption expectations (block-aligned input)
        pad_len = (CIPHER_BLOCK_SIZE - (len(data) % CIPHER_BLOCK_SIZE)) % CIPHER_BLOCK_SIZE
        if pad_len > 0:
            data += b"\x00" * pad_len

        return cipher.encrypt(data)

    @staticmethod
    def _aes_decrypt(key: bytes, ciphertext: bytes) -> bytes:
        if len(ciphertext) % CIPHER_BLOCK_SIZE:
            raise ValueError("Ciphertext is not block-aligned")
        cipher = AES.new(key, AES.MODE_ECB)
        return cipher.decrypt(ciphertext)

    @staticmethod
    def encrypt_then_mac(key_aes: bytes, shared_secret: bytes, plaintext: bytes) -> bytes:
        ciphertext = CryptoUtils._aes_encrypt(key_aes, plaintext)
        mac = CryptoUtils._hmac_sha256(shared_secret, ciphertext)[:CIPHER_MAC_SIZE]
        return mac + ciphertext

    @staticmethod
    def mac_then_decrypt(aes_key: bytes, shared_secret: bytes, data: bytes) -> bytes:
        """
        Match the C++ firmware:
        - HMAC-SHA256 with shared_secret (32B)
        - MAC is 2 bytes
        - AES-128 ECB decrypt
        """
        if len(data) <= CIPHER_MAC_SIZE:
            raise ValueError("Data too short to contain MAC + ciphertext")

        mac = data[:CIPHER_MAC_SIZE]
        ciphertext = data[CIPHER_MAC_SIZE:]
        if len(ciphertext) % CIPHER_BLOCK_SIZE:
            raise ValueError("Ciphertext is not block-aligned")

        expected_mac = CryptoUtils._hmac_sha256(shared_secret, ciphertext)[:CIPHER_MAC_SIZE]
        if not hmac.compare_digest(mac, expected_mac):
            raise ValueError("Invalid HMAC")

        decrypted = CryptoUtils._aes_decrypt(aes_key, ciphertext)

        return decrypted

    @staticmethod
    def x25519_clamp_scalar(scalar: bytes) -> bytes:
        """Clamp a 32-byte scalar for X25519 (matches MeshCore key_exchange.c)."""
        if len(scalar) != 32:
            raise ValueError("scalar must be 32 bytes")
        s = bytearray(scalar)
        s[0] &= 248
        s[31] &= 63
        s[31] |= 64
        return bytes(s)

    @staticmethod
    def ed25519_expand_seed_to_meshcore_64(seed: bytes) -> bytes:
        """Expand a 32-byte Ed25519 seed to 64-byte MeshCore/orlp format."""
        if len(seed) != 32:
            raise ValueError("seed must be 32 bytes")
        h = hashlib.sha512(seed).digest()
        return CryptoUtils.x25519_clamp_scalar(h[:32]) + h[32:64]

    @staticmethod
    def ed25519_public_from_meshcore_64(meshcore_private_64: bytes) -> bytes:
        """Derive Ed25519 public key from 64-byte MeshCore private key format."""
        if len(meshcore_private_64) != 64:
            raise ValueError("meshcore_private_64 must be 64 bytes")
        return crypto_scalarmult_ed25519_base_noclamp(meshcore_private_64[:32])

    @staticmethod
    def scalarmult(private_key: bytes, public_key: bytes) -> bytes:
        """ECDH shared secret calculation (X25519)."""
        return crypto_scalarmult(private_key, public_key)

    @staticmethod
    def ed25519_pk_to_x25519(ed25519_public_key: bytes) -> bytes:
        """Convert Ed25519 public key to X25519 public key."""
        return crypto_sign_ed25519_pk_to_curve25519(ed25519_public_key)

    @staticmethod
    def ed25519_sk_to_x25519(ed25519_private_key: bytes) -> bytes:
        """Convert Ed25519 private key to X25519 private key."""
        return crypto_sign_ed25519_sk_to_curve25519(ed25519_private_key)

    @staticmethod
    def scalarmult_base(private_key: bytes) -> bytes:
        """Generate X25519 public key from private key."""
        return crypto_scalarmult_base(private_key)
