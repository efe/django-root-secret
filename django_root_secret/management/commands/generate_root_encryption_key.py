from django.core.management.base import BaseCommand, CommandError

from django_root_secret.crypto import generate_root_encryption_key
from django_root_secret.env import ensure_path_is_gitignored, env_file_path, write_root_key_file


class Command(BaseCommand):
    help = "Create an <env>.env file containing a single ROOT_ENCRYPTION_KEY."

    def add_arguments(self, parser):
        parser.add_argument("--env", required=True, help="Environment name used for the <env>.env file.")

    def handle(self, *args, **options):
        try:
            path = env_file_path(options["env"])
        except ValueError as exc:
            raise CommandError(str(exc)) from exc

        root_key = generate_root_encryption_key()
        try:
            write_root_key_file(path, root_key)
        except FileExistsError as exc:
            raise CommandError(f"Environment file already exists: {path}") from exc

        gitignore_updated = ensure_path_is_gitignored(path)

        self.stdout.write(f"Created root encryption key file: {path}")
        if gitignore_updated:
            self.stdout.write(f"Added {path.name} to {path.parent / '.gitignore'}")
        else:
            self.stdout.write(f"{path.name} is already present in {path.parent / '.gitignore'}")
