# secure_files

Encrypts, decrypts and shreds files for one local Linux or WSL user. Written in C17 with libsodium.

## Scope

A local single user command line tool for Linux and WSL. It encrypts, decrypts and shreds files up to 1 GiB. It operates only in the folder you run it from. Networking, root attackers and SSD wear levelling are out of scope.

## Build

Clone onto the Linux filesystem. Do not use `/mnt/c` because file permissions fail there.

```bash
sudo apt update
sudo apt install build-essential libsodium-dev git
git clone https://github.com/NotoriousElmo/ICS0022.git
cd ICS0022/secure_files
gcc -std=c17 -Wall -Wextra main.c -o secure_files -lsodium

```

## Use

The tool creates `.secure_files/` and `secure_files.log` in the current folder.

```bash
./secure_files init    --user "$(whoami)"
./secure_files encrypt --user "$(whoami)" notes.txt
./secure_files decrypt --user "$(whoami)" notes.txt.enc
./secure_files shred   --user "$(whoami)" notes.txt.enc

```

Paths must be relative and without `..` parent references. Symbolic links are rejected. Keys are stored in `./.secure_files/`. The encrypted files are lost if you lose the key directory. Any error prints `operation failed`. The reason goes to `./secure_files.log`. The log never contains secrets.

## Test

```bash
bash tests/run_tests.sh

```

## Why C17 and libsodium

C17 provides direct control over memory and file handles. Libsodium is audited and hard to misuse. It provides Argon2id, XChaCha20-Poly1305, `secretstream`, `sodium_mlock` and `sodium_memzero`. It is available in the Ubuntu repositories. OpenSSL was not chosen because its API is larger and easier to misuse.

## State after Checkpoint 3

The tool can initialise a user profile. It can encrypt, decrypt and shred files. The `encrypt` command overwrites the original plaintext before deleting it. Symlinked folders are evaluated using `realpath` and rejected if they leave the working directory. Structured logging records all successes and failures to a restricted file. Passwords and keys are kept in locked memory and wiped as soon as they are no longer needed. The code passes all tests.


- Design: [architecture_and_data_flow.md](architecture_and_data_flow.md)
- Threats: [threat_model_matrix.md](threat_model_matrix.md)
