from getpass import getpass

from django.core.management.base import BaseCommand, CommandError

from django_root_secret.crypto import (
    InvalidRootEncryptionKeyError,
    MissingRootEncryptionKeyError,
    encrypt_value,
)
from django_root_secret.env import env_file_path, load_root_key_from_env_file


def mask_plaintext_value(plaintext_value: str) -> str:
    if len(plaintext_value) <= 4:
        return "*" * len(plaintext_value)
    return f"{plaintext_value[:2]}{'*' * (len(plaintext_value) - 4)}{plaintext_value[-2:]}"


class Command(BaseCommand):
    help = "Encrypt a plaintext value using ROOT_ENCRYPTION_KEY from <env>.env."

    def add_arguments(self, parser):
        parser.add_argument("--env", required=True, help="Environment name used for the <env>.env file.")

    def handle(self, *args, **options):
        try:
            path = env_file_path(options["env"])
            root_key = load_root_key_from_env_file(path)
        except (ValueError, MissingRootEncryptionKeyError, InvalidRootEncryptionKeyError) as exc:
            raise CommandError(str(exc)) from exc

        plaintext_value = getpass("Value to encrypt: ")
        if not plaintext_value:
            raise CommandError("Plaintext value cannot be empty.")

        self.stdout.write(f"Plaintext: {mask_plaintext_value(plaintext_value)}")
        encrypted_value = encrypt_value(plaintext_value, root_key)
        self.stdout.write(encrypted_value)
