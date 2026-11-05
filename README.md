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
mkdir -p ~/ics0022
cp -r /mnt/c/Users/marku/desktop/ics0022/secure_files ~/ics0022/
cd ~/ics0022/secure_files
chmod 700 store keys
```

```bash
./secure_files init    --user bob            # create profile
./secure_files encrypt --user bob notes.txt  # -> notes.txt.enc
./secure_files decrypt --user bob notes.txt.enc
./secure_files shred   --user bob notes.txt.enc   # deletes the key and the .enc file
```

## State after Checkpoint 2

- Can initialise user
- Can encrypt file
- Can decrypt file
