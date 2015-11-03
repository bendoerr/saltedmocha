package com.bendoerr.saltedmocha.nacl;

import com.bendoerr.saltedmocha.CryptoException;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;

import static com.bendoerr.saltedmocha.CryptoException.exception;
import static com.bendoerr.saltedmocha.Util.checkedArrayCopy;
import static com.bendoerr.saltedmocha.Util.validateLength;
import static com.bendoerr.saltedmocha.nacl.CryptoVerify.crypto_verify_32;

/**
 * <p>CryptoAuth class.</p>
 */
public class CryptoAuth {

    /** Constant <code>crypto_auth_hmacsha256_BYTES=32</code> */
    public static final int crypto_auth_hmacsha256_BYTES = 32;
    /** Constant <code>crypto_auth_hmacsha256_KEYBYTES=32</code> */
    public static final int crypto_auth_hmacsha256_KEYBYTES = 32;

    /** Constant <code>crypto_auth_hmacsha512256_BYTES=32</code> */
    public static final int crypto_auth_hmacsha512256_BYTES = 32;
    /** Constant <code>crypto_auth_hmacsha512256_KEYBYTES=32</code> */
    public static final int crypto_auth_hmacsha512256_KEYBYTES = 32;

    /** Constant <code>crypto_auth_BYTES=crypto_auth_hmacsha512256_BYTES</code> */
    public static final int crypto_auth_BYTES = crypto_auth_hmacsha512256_BYTES;
    /** Constant <code>crypto_auth_KEYBYTES=crypto_auth_hmacsha512256_KEYBYTES</code> */
    public static final int crypto_auth_KEYBYTES = crypto_auth_hmacsha512256_KEYBYTES;

    /**
     * <p>crypt_auth.</p>
     *
     * @param a_out an array of byte.
     * @param m an array of byte.
     * @param k an array of byte.
     * @throws com.bendoerr.saltedmocha.CryptoException if any.
     */
    public static void crypt_auth(byte[] a_out, byte[] m, byte[] k) throws CryptoException {
        crypto_auth_hmacsha512256(a_out, m, k);
    }

    /**
     * <p>crypto_auth.</p>
     *
     * @param m an array of byte.
     * @param k an array of byte.
     * @return an array of byte.
     * @throws com.bendoerr.saltedmocha.CryptoException if any.
     */
    public static byte[] crypto_auth(byte[] m, byte[] k) throws CryptoException {
        return crypto_auth_hmacsha512256(m, k);
    }

    /**
     * <p>crypto_auth_verify.</p>
     *
     * @param a an array of byte.
     * @param m an array of byte.
     * @param k an array of byte.
     * @throws com.bendoerr.saltedmocha.CryptoException if any.
     */
    public static void crypto_auth_verify(byte[] a, byte[] m, byte[] k) throws CryptoException {
        crypto_auth_hmacsha512256_verify(a, m, k);
    }

    /**
     * <p>crypto_auth_hmacsha256.</p>
     *
     * @param a_out an array of byte.
     * @param m an array of byte.
     * @param k an array of byte.
     * @throws com.bendoerr.saltedmocha.CryptoException if any.
     */
    public static void crypto_auth_hmacsha256(byte[] a_out, byte[] m, byte[] k) throws CryptoException {
        validateLength(k, crypto_auth_hmacsha256_KEYBYTES,
                "auth key", "crypto_auth_hmacsha256_KEYBYTES");

        checkedArrayCopy(
                hmac(m, k, new SHA256Digest()), 0,
                a_out, 0, crypto_auth_hmacsha256_BYTES);
    }

    /**
     * <p>crypto_auth_hmacsha256.</p>
     *
     * @param m an array of byte.
     * @param k an array of byte.
     * @return an array of byte.
     * @throws com.bendoerr.saltedmocha.CryptoException if any.
     */
    public static byte[] crypto_auth_hmacsha256(byte[] m, byte[] k) throws CryptoException {
        byte[] a_out = new byte[crypto_auth_hmacsha256_BYTES];
        crypto_auth_hmacsha256(a_out, m, k);
        return a_out;
    }

    /**
     * <p>crypto_auth_hmacsha256_verify.</p>
     *
     * @param a an array of byte.
     * @param m an array of byte.
     * @param k an array of byte.
     * @throws com.bendoerr.saltedmocha.CryptoException if any.
     */
    public static void crypto_auth_hmacsha256_verify(byte[] a, byte[] m, byte[] k) throws CryptoException {
        validateLength(k, crypto_auth_hmacsha256_KEYBYTES,
                "auth key", "crypto_auth_hmacsha256_KEYBYTES");

        validateLength(a, crypto_auth_hmacsha256_BYTES,
                "auth hash", "crypto_auth_hmacsha256_BYTES");

        byte[] a2 = crypto_auth_hmacsha256(m, k);
        if (!crypto_verify_32(a, a2))
            throw exception("failed to verify");
    }

    /**
     * <p>crypto_auth_hmacsha512256.</p>
     *
     * @param m an array of byte.
     * @param k an array of byte.
     * @return an array of byte.
     * @throws com.bendoerr.saltedmocha.CryptoException if any.
     */
    public static byte[] crypto_auth_hmacsha512256(byte[] m, byte[] k) throws CryptoException {
        byte[] a_out = new byte[crypto_auth_hmacsha512256_BYTES];
        crypto_auth_hmacsha512256(a_out, m, k);
        return a_out;
    }

    /**
     * <p>crypto_auth_hmacsha512256.</p>
     *
     * @param a_out an array of byte.
     * @param m an array of byte.
     * @param k an array of byte.
     * @throws com.bendoerr.saltedmocha.CryptoException if any.
     */
    public static void crypto_auth_hmacsha512256(byte[] a_out, byte[] m, byte[] k) throws CryptoException {
        validateLength(k, crypto_auth_hmacsha512256_KEYBYTES,
                "auth key", "crypto_auth_hmacsha512256_KEYBYTES");

        checkedArrayCopy(
                hmac(m, k, new SHA512Digest()), 0,
                a_out, 0, crypto_auth_hmacsha512256_BYTES);
    }

    /**
     * <p>crypto_auth_hmacsha512256_verify.</p>
     *
     * @param a an array of byte.
     * @param m an array of byte.
     * @param k an array of byte.
     * @throws com.bendoerr.saltedmocha.CryptoException if any.
     */
    public static void crypto_auth_hmacsha512256_verify(byte[] a, byte[] m, byte[] k) throws CryptoException {
        validateLength(k, crypto_auth_hmacsha512256_KEYBYTES,
                "auth key", "crypto_auth_hmacsha512256_KEYBYTES");

        validateLength(a, crypto_auth_hmacsha512256_BYTES,
                "auth hash", "crypto_auth_hmacsha512256_BYTES");

        byte[] a2 = crypto_auth_hmacsha512256(m, k);
        if (!crypto_verify_32(a, a2))
            throw exception("failed to verify");
    }

    private static byte[] hmac(byte[] m, byte[] k, Digest d) {
        HMac hmac = new HMac(d);
        hmac.init(new KeyParameter(k));
        hmac.update(m, 0, m.length);

        byte[] h = new byte[d.getDigestSize()];
        hmac.doFinal(h, 0);
        return h;
    }
}
