"""Secrets at rest: Fernet encryption for settings-held credentials.

Key source: LIBELLA_SECRET_KEY env (urlsafe-base64 32 bytes) or an
auto-generated key file (0600) in the data dir. Losing the key loses
stored secrets; back it up with the data dir.
"""
import os
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken


class SecretBox:
    def __init__(self, data_dir: str | Path):
        env = os.environ.get("LIBELLA_SECRET_KEY")
        if env:
            self._fernet = Fernet(env.encode() if isinstance(env, str) else env)
        else:
            keyfile = Path(data_dir) / "secret.key"
            if keyfile.exists():
                key = keyfile.read_bytes().strip()
            else:
                key = Fernet.generate_key()
                keyfile.write_bytes(key)
                keyfile.chmod(0o600)
            self._fernet = Fernet(key)

    def encrypt(self, plaintext: str) -> str:
        return self._fernet.encrypt(plaintext.encode()).decode()

    def decrypt(self, token: str) -> str:
        return self._fernet.decrypt(token.encode()).decode()

    def decrypt_or_plain(self, value: str) -> str:
        """Legacy plaintext rows (pre-encryption) are read once and re-encrypted
        by the caller on next write."""
        try:
            return self.decrypt(value)
        except (InvalidToken, ValueError):
            return value
