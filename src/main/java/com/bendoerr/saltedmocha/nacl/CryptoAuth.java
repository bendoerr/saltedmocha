package com.bendoerr.saltedmocha.nacl;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;

import static com.bendoerr.saltedmocha.nacl.CryptoVerify.crypto_verify_32;

public class CryptoAuth {
    public static final int crypto_auth_hmacsha256_BYTES = 32;
    public static final int crypto_auth_hmacsha256_KEYBYTES = 32;
    public static final int crypto_auth_hmacsha512256_BYTES = 32;
    public static final int crypto_auth_hmacsha512256_KEYBYTES = 32;
    public static final int crypto_auth_BYTES = crypto_auth_hmacsha512256_BYTES;
    public static final int crypto_auth_KEYBYTES = crypto_auth_hmacsha512256_KEYBYTES;

    public static byte[] crypto_auth(byte[] m, byte[] k) {
        return crypto_auth_hmacsha512256(m, k);
    }

    public static void crypto_auth_verify(byte[] a, byte[] m, byte[] k) {
        crypto_auth_hmacsha512256_verify(a, m, k);
    }

    public static byte[] crypto_auth_hmacsha256(byte[] m, byte[] k) {
        if (k.length != crypto_auth_hmacsha256_KEYBYTES)
            throw new IllegalArgumentException(
                    "k.length is not crypto_auth_hmacsha256_KEYBYTES.");

        return hmac(m, k, new SHA256Digest(), crypto_auth_hmacsha256_BYTES);
    }

    public static void crypto_auth_hmacsha256_verify(byte[] a, byte[] m, byte[] k) {
        if (k.length != crypto_auth_hmacsha256_KEYBYTES)
            throw new IllegalArgumentException(
                    "k.length is not crypto_auth_hmacsha256_KEYBYTES.");

        if (a.length != crypto_auth_hmacsha256_BYTES)
            throw new IllegalArgumentException(
                    "a.length is not crypto_auth_hmacsha256_BYTES");

        byte[] a2 = crypto_auth_hmacsha256(m, k);
        if (!crypto_verify_32(a, a2))
            throw new CryptoAuthException("failed to verify");
    }

    public static byte[] crypto_auth_hmacsha512256(byte[] m, byte[] k) {
        if (k.length != crypto_auth_hmacsha512256_KEYBYTES)
            throw new IllegalArgumentException(
                    "k.length is not crypto_auth_hmacsha512256_KEYBYTESS.");

        byte[] h512 = hmac(m, k, new SHA512Digest(), 64);
        byte[] h256 = new byte[crypto_auth_hmacsha512256_BYTES];
        System.arraycopy(h512, 0, h256, 0, crypto_auth_hmacsha512256_BYTES);
        return h256;
    }

    public static void crypto_auth_hmacsha512256_verify(byte[] a, byte[] m, byte[] k) {
        if (k.length != crypto_auth_hmacsha512256_KEYBYTES)
            throw new IllegalArgumentException(
                    "k.length is not crypto_auth_hmacsha512256_KEYBYTESS.");

        if (a.length != crypto_auth_hmacsha512256_BYTES)
            throw new IllegalArgumentException(
                    "a.length is not crypto_auth_hmacsha512256_BYTES");

        byte[] a2 = crypto_auth_hmacsha512256(m, k);
        if (!crypto_verify_32(a, a2))
            throw new CryptoAuthException("failed to verify");
    }

    private static byte[] hmac(byte[] m, byte[] k, Digest d, int outlen) {
        HMac hmac = new HMac(d);
        hmac.init(new KeyParameter(k));
        hmac.update(m, 0, m.length);

        byte[] h = new byte[outlen];
        hmac.doFinal(h, 0);
        return h;
    }

    public static class CryptoAuthException extends RuntimeException {
        public CryptoAuthException(String message) {
            super(message);
        }
    }
}
