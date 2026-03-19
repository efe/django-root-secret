import base64
import hashlib
from typing import Final

from cryptography.fernet import Fernet, InvalidToken

ROOT_ENCRYPTION_KEY_ENV_VAR: Final[str] = "ROOT_ENCRYPTION_KEY"


class RootSecretError(Exception):
    """Base exception for package errors."""


class MissingRootEncryptionKeyError(RootSecretError):
    """Raised when a required root encryption key is not available."""


class InvalidRootEncryptionKeyError(RootSecretError):
    """Raised when a root encryption key cannot initialize Fernet."""


class SecretDecryptionError(RootSecretError):
    """Raised when a secret cannot be decrypted."""


def generate_root_encryption_key() -> str:
    return Fernet.generate_key().decode("ascii")


def normalize_root_encryption_key(raw_key: str) -> str:
    key = raw_key.strip()
    if not key:
        raise InvalidRootEncryptionKeyError("Root encryption key cannot be empty.")

    try:
        Fernet(key.encode("ascii"))
        return key
    except (UnicodeEncodeError, ValueError):
        pass

    derived_key = base64.urlsafe_b64encode(hashlib.sha256(key.encode("utf-8")).digest())
    try:
        Fernet(derived_key)
    except ValueError as exc:
        raise InvalidRootEncryptionKeyError("Root encryption key is invalid.") from exc
    return derived_key.decode("ascii")


def build_fernet(raw_key: str) -> Fernet:
    normalized_key = normalize_root_encryption_key(raw_key)
    return Fernet(normalized_key.encode("ascii"))


def encrypt_value(value: str, raw_key: str) -> str:
    return build_fernet(raw_key).encrypt(value.encode("utf-8")).decode("ascii")


def decrypt_value(encrypted_value: str, raw_key: str) -> str:
    try:
        decrypted = build_fernet(raw_key).decrypt(encrypted_value.encode("ascii"))
    except InvalidToken as exc:
        raise SecretDecryptionError("Encrypted value could not be decrypted with the root encryption key.") from exc
    except UnicodeEncodeError as exc:
        raise SecretDecryptionError("Encrypted value must be ASCII-safe text.") from exc
    return decrypted.decode("utf-8")
