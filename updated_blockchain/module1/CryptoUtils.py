import hashlib
import os
from typing import Tuple
from ecdsa import SigningKey, VerifyingKey, SECP256k1, BadSignatureError
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class CryptoUtils:

    @staticmethod
    def sha256(data: str) -> str:
        return hashlib.sha256(data.encode("utf-8")).hexdigest()

    @staticmethod
    def generate_keypair() -> Tuple[SigningKey, VerifyingKey]:
        private_key = SigningKey.generate(curve=SECP256k1)
        public_key = private_key.get_verifying_key()
        return private_key, public_key

    @staticmethod
    def sign_data(data: str, private_key: SigningKey) -> bytes:
        return private_key.sign(data.encode("utf-8"))

    @staticmethod
    def verify_signature(
        data: str,
        signature: bytes,
        public_key: VerifyingKey
    ) -> bool:
        try:
            public_key.verify(signature, data.encode("utf-8"))
            return True
        except BadSignatureError:
            return False

    @staticmethod
    def public_key_to_address(public_key: VerifyingKey) -> str:
        pubkey_bytes = public_key.to_string()
        hash_result = hashlib.sha256(pubkey_bytes).hexdigest()
        return "0x" + hash_result[-40:]

    @staticmethod
    def generate_dh_keypair() -> Tuple[SigningKey, VerifyingKey]:
        """
        Generate ECDH keypair using SECP256k1
        """
        private_key = SigningKey.generate(curve=SECP256k1)
        public_key = private_key.get_verifying_key()
        return private_key, public_key

    @staticmethod
    def derive_shared_secret(
        private_key: SigningKey,
        peer_public_key: VerifyingKey
    ) -> bytes:
        """
        ECDH shared secret derivation
        """
        priv_scalar = private_key.privkey.secret_multiplier
        pub_point = peer_public_key.pubkey.point
        shared_point = pub_point * priv_scalar
        return shared_point.x().to_bytes(32, "big")

    @staticmethod
    def derive_session_key(shared_secret: bytes) -> bytes:
        """
        Derive 256-bit AES key
        """
        return hashlib.sha256(shared_secret).digest()

    @staticmethod
    def encrypt_message(key: bytes, plaintext: bytes) -> dict:
        """
        Returns: { nonce, ciphertext }
        """
        aes = AESGCM(key)
        nonce = os.urandom(12)
        ciphertext = aes.encrypt(nonce, plaintext, None)

        return {
            "nonce": nonce.hex(),
            "ciphertext": ciphertext.hex()
        }

    @staticmethod
    def decrypt_message(key: bytes, enc: dict) -> bytes:
        aes = AESGCM(key)
        nonce = bytes.fromhex(enc["nonce"])
        ciphertext = bytes.fromhex(enc["ciphertext"])
        return aes.decrypt(nonce, ciphertext, None)
