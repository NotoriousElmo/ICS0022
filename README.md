# Secure File Encryption & Management System (SFE)

## Project Scope
A command-line interface (CLI) tool for secure encrypted file storage, retrieval, and cryptographic deletion. SFE utilizes a local envelope encryption architecture (MEK/DEK) with zero-knowledge password proofs to ensure data confidentiality and integrity against offline, physical, and local privilege escalation threats.

## Technology Stack & Library Justifications

* **Language:** `Rust` 
  * *Justification:* Enforces strict memory safety guarantees (ownership and borrowing) at compile-time, mathematically eliminating buffer overflows, use-after-free, and dangling pointer vulnerabilities inherent in C/C++.
* **Cryptography:** `chacha20poly1305`
  * *Justification:* Provides Authenticated Encryption with Associated Data (AEAD). We utilize the `XChaCha20Poly1305` variant; its extended 192-bit nonce space eliminates the risk of nonce-reuse collisions.
* **Key Derivation:** `argon2`
  * *Justification:* The current OWASP-recommended standard. Tunable memory and CPU cost parameters make GPU/ASIC-based dictionary and brute-force attacks financially unviable.
* **Memory Protection:** `secrecy`
  * *Justification:* Actively prevents RAM scraping and cold-boot attacks by explicitly zeroizing memory allocations (passwords, keys) the instant they fall out of scope.
* **Randomness:** `rand` (with `OsRng`)
  * *Justification:* Wraps the operating system's Cryptographically Secure Pseudorandom Number Generator (CSPRNG) for secure key and nonce generation.
* **CLI Parsing:** `clap`
  * *Justification:* Provides robust, secure parsing of user input and paths, forming the first layer of defense against injection attacks.

## Build & Setup Instructions

These instructions assume execution on a clean machine (Linux/macOS/Windows).

### 1. Prerequisites
Install the Rust toolchain (includes `cargo` and `rustc`):
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

### 2. Build the Project
Clone the repository and compile the release binary:
```bash
git clone <your-repo-url>
cd sfe
cargo build --release
```
The compiled binary will be located at `target/release/sfe`.

### 3. Usage Examples
*(Note: These commands represent the target CLI interface for Checkpoint 2)*

**Initialize a user (first run):**
```bash
./target/release/sfe init --user alice
```

**Encrypt a file:**
```bash
./target/release/sfe encrypt --user alice /path/to/target.txt
```

**Decrypt a file:**
```bash
./target/release/sfe decrypt --user alice /path/to/target.txt.enc
```

**Securely delete a file (Crypto-shredding):**
```bash
./target/release/sfe shred --user alice /path/to/target.txt.enc
```