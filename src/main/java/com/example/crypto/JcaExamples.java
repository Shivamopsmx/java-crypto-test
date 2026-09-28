package com.example.crypto;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.util.Random;

/**
 * Java Cryptography Architecture (JCA) usage — a spread of algorithms and a few
 * deliberate misuse patterns for CBOM + cryptographic vulnerability testing.
 * Not for production use.
 */
public class JcaExamples {

    // --- Hashing --------------------------------------------------------
    public byte[] md5(byte[] data) throws Exception {
        return MessageDigest.getInstance("MD5").digest(data);          // MD5 — broken
    }

    public byte[] sha1(byte[] data) throws Exception {
        return MessageDigest.getInstance("SHA-1").digest(data);        // SHA-1 — deprecated
    }

    public byte[] sha256(byte[] data) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(data);      // SHA-256 — ok
    }

    // --- MAC ------------------------------------------------------------
    public byte[] hmacSha256(byte[] key, byte[] msg) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key, "HmacSHA256"));
        return mac.doFinal(msg);                                       // HMAC-SHA256 — ok
    }

    // --- Symmetric encryption ------------------------------------------
    public byte[] aesEcb(byte[] key, byte[] data) throws Exception {
        Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding");         // MISUSE: ECB mode
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"));
        return c.doFinal(data);
    }

    public byte[] aesGcm(byte[] key, byte[] data) throws Exception {
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");            // AES-GCM — ok
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, iv));
        return c.doFinal(data);
    }

    public byte[] aesCbcHardcodedIv(byte[] key, byte[] data) throws Exception {
        byte[] iv = new byte[16];                                     // MISUSE: hardcoded/zero IV
        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
        return c.doFinal(data);
    }

    public byte[] tripleDes(byte[] key, byte[] data) throws Exception {
        Cipher c = Cipher.getInstance("DESede/CBC/PKCS5Padding");      // 3DES — weak (Sweet32)
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "DESede"), new IvParameterSpec(new byte[8]));
        return c.doFinal(data);
    }

    public byte[] des(byte[] key, byte[] data) throws Exception {
        Cipher c = Cipher.getInstance("DES/CBC/PKCS5Padding");         // DES — broken (56-bit)
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "DES"), new IvParameterSpec(new byte[8]));
        return c.doFinal(data);
    }

    // --- Asymmetric (quantum-vulnerable) -------------------------------
    public KeyPair rsa1024() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(1024);                                         // MISUSE: RSA key < 2048
        return kpg.generateKeyPair();
    }

    public KeyPair rsa2048() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);                                         // RSA-2048 — quantum-vulnerable
        return kpg.generateKeyPair();
    }

    public KeyPair ecP256() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));          // ECDSA P-256 — quantum-vulnerable
        return kpg.generateKeyPair();
    }

    // --- Signatures -----------------------------------------------------
    public byte[] signSha256Rsa(KeyPair kp, byte[] data) throws Exception {
        Signature s = Signature.getInstance("SHA256withRSA");         // ok
        s.initSign(kp.getPrivate());
        s.update(data);
        return s.sign();
    }

    public byte[] signSha1Rsa(KeyPair kp, byte[] data) throws Exception {
        Signature s = Signature.getInstance("SHA1withRSA");           // MISUSE: SHA-1 signature
        s.initSign(kp.getPrivate());
        s.update(data);
        return s.sign();
    }

    // --- Random misuse --------------------------------------------------
    public SecretKey insecureAesKey() {
        byte[] key = new byte[16];
        new Random().nextBytes(key);                                  // MISUSE: java.util.Random for key
        return new SecretKeySpec(key, "AES");
    }

    public SecretKey secureAesKey() throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(256, new SecureRandom());                             // ok
        return kg.generateKey();
    }
}
