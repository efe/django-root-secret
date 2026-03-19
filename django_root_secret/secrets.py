import os

from .crypto import ROOT_ENCRYPTION_KEY_ENV_VAR, MissingRootEncryptionKeyError, decrypt_value


def get_secret(encrypted_value: str) -> str:
    raw_key = os.environ.get(ROOT_ENCRYPTION_KEY_ENV_VAR)
    if not raw_key:
        raise MissingRootEncryptionKeyError(
            f"{ROOT_ENCRYPTION_KEY_ENV_VAR} environment variable is required."
        )
    return decrypt_value(encrypted_value, raw_key)
