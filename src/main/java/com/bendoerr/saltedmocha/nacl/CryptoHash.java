package com.bendoerr.saltedmocha.nacl;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class CryptoHash {

    public static final int crypto_hash_sha256_BYTES = 32;
    public static final int crypto_hash_sha512_BYTES = 64;
    public static final int crypto_hash_BYTES = crypto_hash_sha512_BYTES;

    /**
     * The crypto_hash function hashes a message m. It returns a hash h. The
     * output length h.size() is always crypto_hash_BYTES.
     */
    public static byte[] crypto_hash(byte[] m) {
        return crypto_hash_sha512(m);
    }

    public static byte[] crypto_hash_sha256(byte[] m) {
        return hash(m, "SHA-256");
    }

    public static byte[] crypto_hash_sha512(byte[] m) {
        return hash(m, "SHA-512");
    }
    private static byte[] hash(byte[] m, String h) {
        MessageDigest md;
        try {
            md = MessageDigest.getInstance(h);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        md.update(m);
        return md.digest();
    }
}
