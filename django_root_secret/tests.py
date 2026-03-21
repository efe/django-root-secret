import os
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import SimpleTestCase

from django_root_secret.crypto import MissingRootEncryptionKeyError, SecretDecryptionError, encrypt_value
from django_root_secret.secrets import get_secret


class GenerateRootEncryptionKeyCommandTests(SimpleTestCase):
    def test_creates_env_file_and_prints_key_and_location(self):
        with TemporaryDirectory() as temp_dir:
            output = StringIO()
            with mock.patch("pathlib.Path.cwd", return_value=Path(temp_dir)):
                call_command("generate_root_encryption_key", env="development", stdout=output)

            env_file = Path(temp_dir) / "development.env"
            self.assertTrue(env_file.exists())
            content = env_file.read_text(encoding="utf-8")
            self.assertIn("ROOT_ENCRYPTION_KEY=", content)
            rendered_output = output.getvalue()
            self.assertTrue(rendered_output.strip())
            self.assertIn(str(env_file), rendered_output)
            self.assertIn("Added development.env to", rendered_output)

    def test_adds_env_file_to_gitignore_when_missing(self):
        with TemporaryDirectory() as temp_dir:
            output = StringIO()
            gitignore_path = Path(temp_dir) / ".gitignore"
            gitignore_path.write_text(".venv/\n", encoding="utf-8")

            with mock.patch("pathlib.Path.cwd", return_value=Path(temp_dir)):
                call_command("generate_root_encryption_key", env="development", stdout=output)

            self.assertIn("development.env\n", gitignore_path.read_text(encoding="utf-8"))
            self.assertIn("Added development.env to", output.getvalue())

    def test_reports_when_env_file_is_already_gitignored(self):
        with TemporaryDirectory() as temp_dir:
            output = StringIO()
            gitignore_path = Path(temp_dir) / ".gitignore"
            gitignore_path.write_text("development.env\n", encoding="utf-8")

            with mock.patch("pathlib.Path.cwd", return_value=Path(temp_dir)):
                call_command("generate_root_encryption_key", env="development", stdout=output)

            self.assertIn("already present", output.getvalue())

    def test_creates_env_file_with_private_permissions(self):
        with TemporaryDirectory() as temp_dir:
            with mock.patch("pathlib.Path.cwd", return_value=Path(temp_dir)):
                call_command("generate_root_encryption_key", env="development")

            env_file = Path(temp_dir) / "development.env"
            self.assertEqual(env_file.stat().st_mode & 0o777, 0o600)

    def test_raises_when_env_file_exists(self):
        with TemporaryDirectory() as temp_dir:
            env_file = Path(temp_dir) / "development.env"
            env_file.write_text("ROOT_ENCRYPTION_KEY=existing\n", encoding="utf-8")

            with mock.patch("pathlib.Path.cwd", return_value=Path(temp_dir)):
                with self.assertRaises(CommandError):
                    call_command("generate_root_encryption_key", env="development")


class EncryptSecretCommandTests(SimpleTestCase):
    def test_encrypts_value_with_env_file_key(self):
        with TemporaryDirectory() as temp_dir:
            call_command_output = StringIO()
            with mock.patch("pathlib.Path.cwd", return_value=Path(temp_dir)):
                call_command("generate_root_encryption_key", env="production")
                with mock.patch(
                    "django_root_secret.management.commands.encrypt_secret.getpass",
                    return_value="super-secret",
                ):
                    call_command(
                        "encrypt_secret",
                        env="production",
                        stdout=call_command_output,
                    )

            output_lines = call_command_output.getvalue().splitlines()
            self.assertIn("Plaintext: su********et", output_lines)

            encrypted_value = output_lines[-1]
            env_file = Path(temp_dir) / "production.env"
            root_key = [
                line.split("=", 1)[1]
                for line in env_file.read_text(encoding="utf-8").splitlines()
                if line.startswith("ROOT_ENCRYPTION_KEY=")
            ][0]
            self.assertEqual(get_secret_with_key(encrypted_value, root_key), "super-secret")

    def test_raises_when_env_file_is_missing(self):
        with TemporaryDirectory() as temp_dir:
            with mock.patch("pathlib.Path.cwd", return_value=Path(temp_dir)):
                with self.assertRaises(CommandError):
                    call_command("encrypt_secret", env="missing")

    def test_raises_when_prompted_value_is_empty(self):
        with TemporaryDirectory() as temp_dir:
            with mock.patch("pathlib.Path.cwd", return_value=Path(temp_dir)):
                call_command("generate_root_encryption_key", env="production")
                with mock.patch(
                    "django_root_secret.management.commands.encrypt_secret.getpass",
                    return_value="",
                ):
                    with self.assertRaisesMessage(CommandError, "Plaintext value cannot be empty."):
                        call_command("encrypt_secret", env="production")


class GetSecretTests(SimpleTestCase):
    def test_decrypts_using_root_encryption_key_env_var(self):
        encrypted = encrypt_value("plain-value", "not-a-fernet-key")
        with mock.patch.dict(os.environ, {"ROOT_ENCRYPTION_KEY": "not-a-fernet-key"}, clear=False):
            self.assertEqual(get_secret(encrypted), "plain-value")

    def test_raises_when_root_key_env_var_is_missing(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(MissingRootEncryptionKeyError):
                get_secret("token")

    def test_raises_when_secret_cannot_be_decrypted(self):
        encrypted = encrypt_value("plain-value", "first-key")
        with mock.patch.dict(os.environ, {"ROOT_ENCRYPTION_KEY": "second-key"}, clear=False):
            with self.assertRaises(SecretDecryptionError):
                get_secret(encrypted)


def get_secret_with_key(encrypted_value: str, root_key: str) -> str:
    with mock.patch.dict(os.environ, {"ROOT_ENCRYPTION_KEY": root_key}, clear=False):
        return get_secret(encrypted_value)
