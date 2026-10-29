# secure_files

`passphrase -> Argon2id -> KEK -> unwraps MEK -> unwraps per-file DEK -> XChaCha20-Poly1305`

## Build

Needs a C compiler and libsodium WSL.

```powershell
wsl -d Ubuntu
```

```bash
sudo apt update
sudo apt install build-essential libsodium-dev
cd secure_files
gcc -std=c17 -Wall -Wextra main.c -o secure_files -lsodium
```

## Use

```bash
./secure_files init    --user alice            # create profile
./secure_files encrypt --user alice notes.txt  # -> notes.txt.enc
./secure_files decrypt --user alice notes.txt.enc
./secure_files shred   --user alice notes.txt.enc   # deletes the key and the .enc file
```
