package com.example.crypto;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.MessageDigest;
import java.util.Arrays;

/**
 * Authentication / password-storage helpers — a good/bad mix for exercising
 * KDF- and hash-misuse detection. Not for production use.
 */
public class PasswordUtil {

    // MISUSE: password stored as a fast unsalted hash
    public byte[] hashPasswordMd5(String password) throws Exception {
        return MessageDigest.getInstance("MD5").digest(password.getBytes());   // password-as-MD5
    }

    // MISUSE: SHA-256 directly on password (no KDF, no salt)
    public byte[] hashPasswordSha256(String password) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(password.getBytes());
    }

    // OK: PBKDF2-HMAC-SHA256 with a proper iteration count
    public byte[] hashPasswordPbkdf2(char[] password, byte[] salt) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(password, salt, 210_000, 256);
        SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        return f.generateSecret(spec).getEncoded();
    }

    // MISUSE: non-constant-time comparison of authentication material
    public boolean verifyTokenInsecure(byte[] provided, byte[] expected) {
        return Arrays.equals(provided, expected);                    // timing side-channel
    }

    // MISUSE: hardcoded key material in source
    private static final byte[] API_SECRET = "hardcoded-super-secret-key-123".getBytes();

    public byte[] getSecret() {
        return API_SECRET;
    }
}
