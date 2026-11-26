# secure_files

Encrypts, decrypts and shreds files for one local Linux/WSL user. Written in C17 with libsodium.

**Scope:** your own files up to 1 GiB, in the folder you run the tool from. No networking, sharing or password
recovery.

## Build

Clone onto the Linux filesystem, not `/mnt/c`.

```bash
sudo apt install build-essential libsodium-dev git
git clone https://github.com/NotoriousElmo/ICS0022.git && cd ICS0022/secure_files
gcc -std=c17 -Wall -Wextra main.c -o secure_files -lsodium
```

## Use

```bash
./secure_files init    --user "$(whoami)"                # create profile (password of 12+ characters)
./secure_files encrypt --user "$(whoami)" notes.txt      # -> notes.txt.enc, removes notes.txt
./secure_files decrypt --user "$(whoami)" notes.txt.enc  # -> notes.txt
./secure_files shred   --user "$(whoami)" notes.txt.enc  # destroys notes.txt.enc and its key
```

- Paths must be relative, without `..`, and not symbolic links.
- Keys are stored in `./.secure_files/`. If you lose it, the encrypted files are lost too.
- Any error prints `operation failed`. The reason goes to `./secure_files.log`, which never contains secrets.

## Test

Run `bash test.sh` in a scratch copy only: it deletes `./.secure_files/`.

## Why C17 and libsodium

C17 gives direct control over memory and file handles. libsodium is audited, hard to misuse, and provides every
primitive the tool needs. OpenSSL is larger and easier to misuse.

## Known limitations

- `encrypt` does not overwrite the original before deleting it.
- A symlinked folder in a path is followed.
- The log records only failures.
- Some error exits skip wiping secrets from memory.

Design: [architecture_and_data_flow.md](architecture_and_data_flow.md) · Threats: [threat_model_matrix.md](threat_model_matrix.md)
