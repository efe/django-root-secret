# django-root-secret

[![Tests](https://github.com/efe/django-root-secret/actions/workflows/tests.yml/badge.svg?branch=main)](https://github.com/efe/django-root-secret/actions/workflows/tests.yml)

`django-root-secret` is a Django package for managing one root encryption key per environment and decrypting encrypted literals at runtime.

`django-root-secret` reduces the number of plaintext secrets you need to manage. Large `.env` files are a common source of configuration errors because variables can be missing, misnamed, outdated, or inconsistent across environments. This package keeps the env file minimal by storing only `ROOT_ENCRYPTION_KEY` there and encrypting the rest.

## Installation

Install the package:

```bash
pip install django-root-secret
```

Add the app to `INSTALLED_APPS`:

```python
INSTALLED_APPS = [
    ...,
    "django_root_secret",
]
```

## Commands

Generate a root key file:

```bash
python manage.py generate_root_encryption_key --env development
```

This creates `development.env` in the current working directory with only:

```dotenv
# This file must only contain ROOT_ENCRYPTION_KEY.
# Encrypt every other secret with this key and keep the file private.
ROOT_ENCRYPTION_KEY=...
```

Encrypt a plaintext secret using that file:

```bash
python manage.py encrypt_secret --env development --value "my-db-password"
```

Use the encrypted output in code and decrypt it with `ROOT_ENCRYPTION_KEY` from the runtime environment:

```python
from django_root_secret import get_secret

DATABASE_PASSWORD = get_secret("gAAAAAB...")
```
