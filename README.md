# java-crypto-test

Java (Maven) project exercising a broad spread of cryptography for testing
**CBOM** generation and **cryptographic vulnerability assessment**. Uses both the
JDK's **JCA** and **BouncyCastle**. **Not for production use.**

## What's inside

**`JcaExamples.java`** (JDK JCA)
- Hash: MD5, SHA-1, SHA-256
- MAC: HMAC-SHA256
- Symmetric: AES-ECB (misuse), AES-GCM, AES-CBC (hardcoded IV, misuse), 3DES, DES
- Asymmetric: RSA-1024 (weak), RSA-2048, EC secp256r1
- Signatures: SHA256withRSA, SHA1withRSA (misuse)
- Random: `java.util.Random` for a key (misuse) vs `SecureRandom`

**`BouncyCastleExamples.java`** (BouncyCastle)
- SHA3-256, AES-GCM engine
- Argon2id (low-memory misuse), PBKDF2 (low-iteration + SHA-1 PRF misuse)
- Ed25519 signature keys

**`PasswordUtil.java`** (auth / password storage)
- Password-as-MD5 / SHA-256 (misuse), PBKDF2-HMAC-SHA256 (ok)
- Non-constant-time token compare (misuse), hardcoded secret (misuse)

## Coverage for the vuln taxonomy
- **Quantum-vulnerable:** RSA, EC, Ed25519
- **Algorithm-intrinsic weak:** MD5, SHA-1, DES, 3DES, RSA-1024
- **Insecure usage (misuse):** ECB mode, hardcoded IV, `java.util.Random` for keys,
  SHA-1 signatures, weak PBKDF2/Argon2 params, unsalted password hashing,
  non-constant-time compare, hardcoded key
- **Modern/ok:** SHA-256, SHA3-256, AES-GCM, HMAC-SHA256, PBKDF2-HMAC-SHA256
