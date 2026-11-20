# Secrets at rest

What is encrypted in Libella's SQLite database, what is not, and what that means
for backups and key rotation.

## Encrypted columns

| Column | Table | Contents |
| --- | --- | --- |
| `auth_json` | `engagements` | engagement auth material: identities (including passwords), GraphQL/OpenAPI hints, test hints |
| `cookies_json` | `auth_contexts` | live session cookies captured by an authenticated login |
| `value_json` | `settings` (`api_token`, `llm_config`) | API bearer token and LLM API key |

Values are Fernet (AES-128-CBC + HMAC) ciphertext, stored as urlsafe-base64
text. `login_flow_json` is *not* encrypted: the login flow deliberately never
persists the password, and it carries only URLs, selectors and the success
assertion.

`DB.query()` / `DB.one()` decrypt the engagement and cookie columns transparently, so callers keep
working with JSON text. Writers must pass secret values through `DB.seal()`;
`POST /api/engagements` and `AuthBrowser.login_flow()` do. Anything that reads
the SQLite file directly sees ciphertext only.

## Key

`SecretBox` uses, in order:

1. `LIBELLA_SECRET_KEY` — a urlsafe-base64 32-byte Fernet key, for deployments
   that provision keys externally (containers, secret managers).
2. `secret.key` next to `libella.db` — generated on first run with `O_EXCL` and
   mode `0600` so two first runs cannot race into two different keys and the
   key is never world-readable, even briefly.

The same key protects `settings`, engagement auth and session cookies. It is
**not** derived from the API token and is not stored in the database.

## Legacy plaintext migration

Rows written before this hardening (or by a writer that bypassed `DB.seal()`)
are distinguished by the historical Fernet prefix `gAAAAA`, not by a versioned
database envelope. With all users of the database stopped and a protected backup,
run `libella --data-dir <directory> --migrate-storage`. This opens no network
listener and loads no plugins. On `DB` open:

- plaintext rows are encrypted in place, then committed;
- existing ciphertext is *verified* first, so a wrong or lost key aborts the
  open with `SecretError` before any row is rewritten;
- after a migration the WAL is checkpointed (`TRUNCATE`) and the database is
  `VACUUM`ed, so the replaced plaintext pages do not remain in the live
  database or WAL;
- the migration is idempotent, but checks the stored credential rows on every open.

A value that looks like ciphertext but does not decrypt (truncated token, key
mismatch) is never treated as plaintext. Reads fail closed.

`settings.api_token` is stored as a JSON-encoded Fernet token
(`json.dumps(ciphertext)`); the ciphertext format itself is unchanged. A
read-only CLI can `json.loads` the settings row and call `SecretBox.decrypt()`
with a provisioned key. `SecretBox.decrypt()` is strict: it raises rather than
returning its input, so a lost key cannot turn the stored ciphertext into a
valid bearer token. Startup likewise fails instead of serving requests with a
ciphertext token.

## Backup and rotation limits

- **Back up `secret.key` with the database.** A database backup without the key
  is unreadable: engagement auth, stored sessions, the API token and the LLM
  key are unrecoverable. Restoring the wrong key fails closed (the app refuses
  to start) rather than silently losing data.
- **Rotation is manual and not implemented.** There is no re-encrypt command
  and no key version stored with the ciphertext. Rotating means: stop Libella,
  decrypt every protected value with the old key, write a new `secret.key` (or
  set `LIBELLA_SECRET_KEY`), re-encrypt and update the rows, then restart. With
  `LIBELLA_SECRET_KEY`, an old key that is still in the environment silently
  keeps working — remove it when rotating.
- **Deleted plaintext is not provably gone.** The migration vacuum removes the
  live pages and truncates the WAL, but filesystem snapshots, SSD wear-levelling,
  SQLite backups and copies of the database made before migration can still
  contain the old plaintext. Treat any pre-hardening backup as sensitive.
- **The key file sits beside the data.** `0600` and the data-dir permissions are
  the only at-rest protection; disk encryption or an external key source
  (`LIBELLA_SECRET_KEY`) is stronger. A process that can read both the database
  and the key can read everything.
- **Evidence files are out of scope.** Screenshots and captured exchanges are
  not encrypted by this layer; they can contain session material observed on
  the target.