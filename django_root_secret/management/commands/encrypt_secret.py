from getpass import getpass

from django.core.management.base import BaseCommand, CommandError

from django_root_secret.crypto import (
    InvalidRootEncryptionKeyError,
    MissingRootEncryptionKeyError,
    encrypt_value,
)
from django_root_secret.env import env_file_path, load_root_key_from_env_file


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

        encrypted_value = encrypt_value(plaintext_value, root_key)
        self.stdout.write(encrypted_value)
