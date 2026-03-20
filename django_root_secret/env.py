import os
from pathlib import Path

from .crypto import MissingRootEncryptionKeyError

ROOT_ENCRYPTION_KEY_FILE_VAR = "ROOT_ENCRYPTION_KEY"
FILE_COMMENT = (
    "# This file must only contain ROOT_ENCRYPTION_KEY.\n"
    "# Encrypt every other secret with this key and keep the file private.\n"
)


def validate_env_name(env_name: str) -> str:
    normalized = env_name.strip()
    if not normalized:
        raise ValueError("Environment name cannot be empty.")

    allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-")
    if any(char not in allowed for char in normalized):
        raise ValueError(
            "Environment name may only contain letters, numbers, underscores, and hyphens."
        )
    return normalized


def env_file_path(env_name: str, base_dir: Path | None = None) -> Path:
    normalized = validate_env_name(env_name)
    directory = Path.cwd() if base_dir is None else Path(base_dir)
    return directory / f"{normalized}.env"


def ensure_path_is_gitignored(path: Path, gitignore_path: Path | None = None) -> bool:
    target_gitignore = path.parent / ".gitignore" if gitignore_path is None else Path(gitignore_path)
    entry = path.name

    if target_gitignore.exists():
        lines = target_gitignore.read_text(encoding="utf-8").splitlines()
    else:
        lines = []

    normalized_entries = {line.strip() for line in lines}
    if entry in normalized_entries:
        return False

    with target_gitignore.open("a", encoding="utf-8") as file_obj:
        if lines and lines[-1].strip():
            file_obj.write("\n")
        file_obj.write(f"{entry}\n")
    return True


def write_root_key_file(path: Path, root_key: str) -> None:
    content = f"{FILE_COMMENT}{ROOT_ENCRYPTION_KEY_FILE_VAR}={root_key}\n"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    fd = os.open(path, flags, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as file_obj:
            file_obj.write(content)
    except Exception:
        path.unlink(missing_ok=True)
        raise


def load_root_key_from_env_file(path: Path) -> str:
    if not path.exists():
        raise MissingRootEncryptionKeyError(f"Environment file does not exist: {path}")

    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        name, value = line.split("=", 1)
        if name.strip() != ROOT_ENCRYPTION_KEY_FILE_VAR:
            continue
        cleaned = value.strip().strip("\"'")
        if not cleaned:
            break
        return cleaned

    raise MissingRootEncryptionKeyError(
        f"{ROOT_ENCRYPTION_KEY_FILE_VAR} is missing from environment file: {path}"
    )
