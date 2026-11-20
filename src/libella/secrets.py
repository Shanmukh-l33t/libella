"""Secrets at rest: Fernet encryption for settings-held credentials.

Key source: LIBELLA_SECRET_KEY env (urlsafe-base64 32 bytes) or an
auto-generated key file (0600) in the data dir. Losing the key loses
stored secrets; back it up with the data dir.
"""
import os
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

# Fernet's version byte (0x80) plus three zero timestamp bytes make every
# token generated before 2242 start with this. Used only to tell legacy
# plaintext apart from ciphertext; either way the value is not trusted.
_FERNET_MARK = "gAAAAA"


class SecretError(RuntimeError):
    """Stored secret is ciphertext that this key cannot decrypt."""


def is_encrypted(value: str) -> bool:
    return isinstance(value, str) and value.startswith(_FERNET_MARK)


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
                # O_EXCL: two first runs must not race into two different keys;
                # mode 0600 applies from creation, not after a chmod window.
                try:
                    fd = os.open(keyfile, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                except FileExistsError:
                    key = keyfile.read_bytes().strip()
                else:
                    with os.fdopen(fd, "wb") as f:
                        f.write(key)
            self._fernet = Fernet(key)

    def encrypt(self, plaintext: str) -> str:
        return self._fernet.encrypt(plaintext.encode()).decode()

    def decrypt(self, token: str) -> str:
        """Strict: plaintext, truncation or a wrong key raises, never returns input."""
        try:
            return self._fernet.decrypt(token.encode()).decode()
        except (InvalidToken, ValueError) as e:
            raise SecretError("stored secret cannot be decrypted: wrong or lost key") from e

    def decrypt_or_plain(self, value: str) -> str:
        """Legacy plaintext rows (pre-encryption) are read once and re-encrypted
        by the caller on next write. Ciphertext must decrypt: a wrong key raises
        instead of handing the ciphertext back as if it were the secret."""
        return self.decrypt(value) if is_encrypted(value) else value
