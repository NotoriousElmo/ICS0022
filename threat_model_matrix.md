# Threat Model: secure_files

**Attackers:** someone with a copy of the disk, another local user, hostile input, tampering on disk.

| ID | Threat | Mitigation | Status |
|---|---|---|---|
| AUTH-01 | Password guessing | Argon2id (256 MiB per guess), salt, 12+ characters | Done |
| AUTH-02 | Secrets left in memory | keys, stream state and plaintext buffers in locked memory (`sodium_mlock`; the tool stops if locking fails), wiped after use; stack cleared after Argon2id (`sodium_stackzero`); core dumps disabled (`setrlimit`); unbuffered stdin | Done |
| AUTH-03 | Profile tampering | authenticated encryption | Done |
| AUTH-04 | Acting as another user | `--user` must equal your login | Done |
| KEY-01 | Nonce or key reuse | random nonces, one key per file | Done |
| KEY-02 | Data left after delete | per-file key in its own `.key` file; `shred` overwrites both files with random bytes, then unlinks them; a failed `decrypt` overwrites its partial output before removing it | Done |
| KEY-03 | Ciphertext tampering | tag per chunk, order and end checked | Done |
| KEY-04 | Swapped key file | key bound to its file ID | Done |
| FILE-01 | Path traversal | relative paths only, no `..`, `realpath` check on the parent folder; paths into `.secure_files/` or to the log are refused, and `encrypt` refuses files with other hard links and its own program file | Done |
| FILE-02 | Check-then-use races | `O_NOFOLLOW` + `fstat` on the open fd; outputs opened with `O_EXCL` | Done |
| FILE-03 | Huge or special files | 64 KiB chunks and a 1 GiB limit | Done |
| ACC-01 | Other users' access | `--user` must equal your login name, files must be owned by you, `0700`/`0600` | Done |
| INJ-01 | Command injection | the tool never calls a shell or `exec`; user names are allowlisted; control characters are rejected | Done |
| LOG-01 | Secrets or forged lines in the log | fixed fields from validated values, no passwords/keys/paths, `0600`, `O_NOFOLLOW` | Done |
| ERR-01 | Errors leak details | the screen only says `operation failed`; details go to the log | Done |

**Accepted risks:**
- root or malware attackers
- no lockout on password tries
- two rare error exits (the repeat-password read fails at `init`, or Argon2id runs out of memory) skip wiping the
  password; that memory is locked, never dumped, and released when the process exits
- losing the key store means losing the files
- overwriting does not reliably erase data on SSDs or journaling/CoW filesystems
- libsodium's 256 MiB Argon2id work area is not locked, so it can reach swap
