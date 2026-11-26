# Threat Model: secure_files

**Attackers:** someone with a copy of the disk, another local user, hostile input, tampering on disk.

| ID | Threat | Mitigation | Status |
|---|---|---|---|
| AUTH-01 | Password guessing | Argon2id (256 MiB per guess), salt, 12+ characters | Done |
| AUTH-02 | Secrets left in memory | locked memory, wiped after use, no core dumps | Partial: stdin buffer, some error exits |
| AUTH-03 | Profile tampering | authenticated encryption | Done |
| AUTH-04 | Acting as another user | `--user` must equal your login | Done |
| KEY-01 | Nonce or key reuse | random nonces, one key per file | Done |
| KEY-02 | Data left after delete | `shred` overwrites, then deletes | Partial: `encrypt` only unlinks the original |
| KEY-03 | Ciphertext tampering | tag per chunk, order and end checked | Done |
| KEY-04 | Swapped key file | key bound to its file ID | Done |
| FILE-01 | Path traversal | no `..`, no absolute paths, no symlinked file | Partial: symlinked folders followed |
| FILE-02 | Check-then-use races | checks on the open handle, `O_EXCL` outputs | Done |
| FILE-03 | Huge or special files | 64 KiB streaming, 1 GiB limit, regular files only | Done |
| ACC-01 | Other users' access | private folders and files, owner check | Done |
| INJ-01 | Command injection | no shell or `exec` is ever called | Done |
| LOG-01 | Secrets in the log | fixed messages only | Done |
| LOG-02 | Weak log | none yet | Partial: failures only, default permissions |
| ERR-01 | Errors leak details | one generic message | Done |

**Accepted risks:**
- root or malware attackers
- no lockout on password tries
- losing the key store means losing the files
- overwriting is not reliable on SSDs or journaling filesystems
