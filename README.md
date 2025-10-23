## ratCORE.Signing

**ratCORE.Signing** is a C# library for **cryptographic file signing and verification** based on **ECDSA-P256 (SHA-256)**.  
It provides all necessary components to securely generate, manage, and use digital signatures — including key generation, signing, and verification.

---

### 🚀 Features

- **Modern Cryptography**
  - Uses **ECDSA-P256** for signatures and **SHA-256** as hash function.
  - Private keys are encrypted using **AES-256-GCM** with keys derived from **PBKDF2-SHA256**.

- **Secure Key Storage**
  - The key file (`.sec.json`) stores the private scalar *D* encrypted with AES-GCM.
  - Each key file includes a salt, nonce, and authentication tag for tamper detection.
  - Password-protected — even if the file is stolen, the private key remains secure.

- **Deterministic Signature Format**
  - Signatures are stored in a dedicated `.ratsig` file using JSON.
  - The signature includes metadata such as algorithm, hash, creation date, and file name hint.
  - The public key and an optional **trusted comment** are part of the signed data.

- **Trust Verification**
  - Each public key has a **KeyId** (`Base64(SHA256(pub))`).
  - Verification can be performed either with the **public key** itself or a **trusted KeyId**.
  - Ensures authenticity even if multiple keys exist.

- **Cross-Platform**
  - Compatible with **Windows**, **Linux**, and **macOS**.
  - Fully implemented in .NET 8, no external dependencies.

---

### 🧩 Components

| Class | Purpose |
|--------|----------|
| **KeyGen** | Generates a new ECDSA key pair, encrypts the private key, and writes a key file (`.sec.json`). |
| **Signer** | Signs files using an encrypted key file and a password. Produces a signature file (`.ratsig`). |
| **Verifier** | Verifies files using their `.ratsig` signature file and a trusted public key or KeyId. |
| **KeyFile** | Defines the structure of an encrypted key file. |
| **SignatureFile** | Defines the structure of a signature file. |

---

### 🔐 File Formats

#### **Key File (`.sec.json`)**

| Field | Description |
|--------|-------------|
| `version` | Format version (currently 1). |
| `alg` | Signature algorithm (`ecdsa-p256`). |
| `aead` | Encryption mode (`aes-256-gcm`). |
| `kdf` | Key derivation info (PBKDF2-SHA256, salt, iterations, key length). |
| `encSeed` | Encrypted private scalar (nonce, ciphertext, tag). |
| `pub` | Base64-encoded uncompressed public key (0x04 || X || Y). |
| `keyId` | Base64-encoded SHA256 hash of the public key. |
| `createdUtc` | ISO 8601 UTC timestamp of key creation. |

#### **Signature File (`.ratsig`)**

| Field | Description |
|--------|-------------|
| `magic` | Constant `"RSIG"`. |
| `version` | Format version (currently 1). |
| `alg` | Signature algorithm (`ecdsa-p256`). |
| `hash` | Hash algorithm (`sha256`). |
| `pub` | Base64-encoded uncompressed public key. |
| `sig` | Base64-encoded DER-encoded ECDSA signature. |
| `comment` | Optional trusted comment (part of signed data). |
| `createdUtc` | ISO 8601 UTC timestamp. |
| `fileName` | Original filename of the signed file. |

---

### 🧩 Example Usage / Quick Start

```csharp
using ratCORE.Signing;

// Generate a new key pair
string keyPath = await KeyGen.GenerateAsync(
    outputDirectory: ".",
    password: "MySecurePassword",
    iterations: 300_000
);

// Sign a file
string sigPath = await Signer.SignFileAsync(
    inputFile: "payload.bin",
    keyFilePath: keyPath,
    password: "MySecurePassword",
    trustedComment: "release build 2025"
);

// Verify the file using its KeyId
bool valid = await Verifier.VerifyFileWithKeyIdAsync(
    inputFile: "payload.bin",
    signaturePath: sigPath,
    expectedKeyIdBase64: "8/zko5PTQ9x5TYiArLapn8CrYAneCt7E/GEtAhH8LEs="
);

Console.WriteLine(valid ? "✅ Signature valid" : "❌ Invalid signature");
```

---

### ⚠️ Error Handling

`ratCORE.Signing` throws descriptive exceptions to simplify debugging and integration.

| Exception | Description |
|-----------|-------------|
| `InvalidDataException` | Invalid key or signature file, or corrupted/cut file. |
| `InvalidOperationException` | Algorithm mismatch or unsupporten curve. |
| `CryptographicException` | Decryption failure (wrong password or tampered file). |
| `IOException` | File not found or insufficient permissions. |

---

### 🧱 Technical Overview

| Component | Purpose |
|------------|----------|
| **ECDSA-P256** | Public-key signature algorithm used for signing and verifying. |
| **SHA-256** | Hashing algorithm used for file and comment digest. |
| **PBKDF2-SHA256** | Derives AES encryption key from password. |
| **AES-256-GCM** | Encrypts private key with authentication tag for integrity. |
| **KeyId** | Trust anchor = `Base64(SHA256(pub))`. Used to verify identity of signer. |

---

### 🛠️ System Requirements

- .NET 8 or higher  
- Supported platforms: **Windows**, **Linux**, **macOS**  
- No external dependencies  

---

### 🧩 About

This project is part of the **ratCORE** framework — a collection of libraries designed for robust, cross-platform, and secure .NET development.

---

**License:** Creative Commons Attribution 4.0 International (CC BY 4.0)  
**Copyright © 2025 ratware**
