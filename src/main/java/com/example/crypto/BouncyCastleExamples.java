package com.example.crypto;

import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.params.Argon2Parameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;

/**
 * BouncyCastle usage — provider-specific primitives, PQC-relevant and
 * password-hashing constructions for CBOM testing. Not for production use.
 */
public class BouncyCastleExamples {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    // SHA3-256 hash (BC low-level API)
    public byte[] sha3(byte[] data) {
        SHA3Digest d = new SHA3Digest(256);
        d.update(data, 0, data.length);
        byte[] out = new byte[d.getDigestSize()];
        d.doFinal(out, 0);
        return out;
    }

    // AES-GCM via BC low-level API
    public GCMBlockCipher aesGcmEngine() {
        return new GCMBlockCipher(new AESEngine());                   // AES-GCM
    }

    // Argon2id password hashing — MISUSE: low memory cost
    public byte[] argon2WeakParams(char[] password, byte[] salt) {
        Argon2Parameters params = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                .withSalt(salt)
                .withMemoryAsKB(1024)     // MISUSE: memory_cost < 64 MB
                .withIterations(1)
                .withParallelism(1)
                .build();
        Argon2BytesGenerator gen = new Argon2BytesGenerator();
        gen.init(params);
        byte[] out = new byte[32];
        gen.generateBytes(password, out);
        return out;
    }

    // PBKDF2 — MISUSE: low iteration count + SHA-1 PRF
    public byte[] pbkdf2Weak(byte[] password, byte[] salt) {
        PKCS5S2ParametersGenerator gen = new PKCS5S2ParametersGenerator();  // defaults to SHA-1
        gen.init(password, salt, 1000);                              // MISUSE: < 100k iterations
        return ((KeyParameter) gen.generateDerivedParameters(256)).getKey();
    }

    // Ed25519 signature key (BC provider)
    public java.security.KeyPair ed25519() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Ed25519", "BC");
        kpg.initialize(new ECGenParameterSpec("Ed25519"), new SecureRandom());
        return kpg.generateKeyPair();                                // EdDSA — quantum-vulnerable
    }
}
