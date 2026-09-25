# Threat Model: Secure File Encryption & Management System

**Methodology:** Threats are evaluated across Authentication, Key Management, and File Handling domains.

## 1. Authentication & Password Handling

| ID | Threat | Attack Vector | Risk | Architectural Mitigation | 
| :--- | :--- | :--- | :--- | :--- | 
| **AUTH-01** | **Offline Brute Force** | Attacker steals `users.json` and uses GPU clusters to brute-force passwords. | **High** | **Argon2id:** Passwords are never stored. Tuned memory/time parameters make GPU scaling financially infeasible. | 
| **AUTH-02** | **Memory Scraping** | Attacker dumps system RAM/swap to recover plaintext passwords or the MEK. | **High** | **Strict Zeroization:** Rust’s `secrecy` crate immediately zeroizes passwords, KEK, and MEK from RAM upon scope exit. | 
| **AUTH-03** | **Metadata Tampering** | Attacker edits `users.json` to bypass auth or alter user metadata. | **Medium** | **AEAD Validation:** `users.json` key payloads use XChaCha20-Poly1305. Alterations invalidate the MAC, securely aborting execution. | 

## 2. Key Management & Cryptography

| ID | Threat | Attack Vector | Risk | Architectural Mitigation | 
| :--- | :--- | :--- | :--- | :--- | 
| **KEY-01** | **Nonce Reuse** | Using the same nonce twice allows attackers to XOR ciphertexts and recover plaintext. | **Critical** | **XChaCha20:** 192-bit extended nonce space combined with CSPRNG makes collision probability mathematically negligible. | 
| **KEY-02** | **Data Remanence** | Standard OS file deletion leaves recoverable ciphertext on the physical disk. | **Medium** | **Crypto-Shredding:** Unique Per-File DEKs. Overwriting/truncating the 72-byte header destroys the DEK, permanently rendering remaining data useless. | 
| **KEY-03** | **Ciphertext Malleability** | Attacker alters encrypted file bytes on disk to manipulate logic upon decryption. | **High** | **Poly1305 Tag:** Verified during decryption prior to disk writes, completely neutralizing chosen-ciphertext attacks. | 

## 3. File Handling & System Interaction

| ID | Threat | Attack Vector | Risk | Architectural Mitigation | 
| :--- | :--- | :--- | :--- | :--- | 
| **FILE-01** | **Path Traversal** | Attacker inputs malicious paths (e.g., `../../../etc/shadow`) to overwrite OS files. | **Critical** | **Input Canonicalization:** Strict resolution of absolute paths. Symlinks pointing outside authorized directories are rejected. | 
| **FILE-02** | **TOCTOU Race Condition** | Attacker swaps a legitimate file with a malicious symlink between path validation and execution. | **High** | **File Descriptor Locking:** Validate file properties (e.g., symlink status) directly on the open file descriptor handle, bypassing path-based races. | 
| **FILE-03** | **Memory Exhaustion (DoS)** | Encrypting large files (e.g., 100GB) entirely in RAM triggers the OS OOM killer. | **Low** | **Chunked Streaming:** Process I/O in fixed 4MB blocks. Memory footprint remains small and constant regardless of file size. | 

## 4. Out of Scope (Accepted Risks)
* **OS-Level Compromise:** Root access, kernel keyloggers, or modified binaries (Evil Maid attacks). Mitigations require hardware layers (Secure Boot) and Full Disk Encryption (LUKS/BitLocker) outside application scope.