package com.bendoerr.saltedmocha.nacl;

import com.bendoerr.saltedmocha.CryptoException;

import static com.bendoerr.saltedmocha.Util.checkedArrayCopy;
import static com.bendoerr.saltedmocha.Util.validateLength;
import static com.bendoerr.saltedmocha.nacl.CryptoOneTimeAuth.crypto_onetimeauth_poly1305;
import static com.bendoerr.saltedmocha.nacl.CryptoOneTimeAuth.crypto_onetimeauth_poly1305_verify;
import static com.bendoerr.saltedmocha.nacl.CryptoStream.crypto_stream_xsalsa20;
import static com.bendoerr.saltedmocha.nacl.CryptoStream.crypto_stream_xsalsa20_xor;
import static org.bouncycastle.util.Arrays.copyOfRange;

/**
 * <p>CryptoSecretBox class.</p>
 */
public class CryptoSecretBox {

    /** Constant <code>crypto_secretbox_xsalsa20poly1305_KEYBYTES=32</code> */
    public static final int crypto_secretbox_xsalsa20poly1305_KEYBYTES = 32;
    /** Constant <code>crypto_secretbox_xsalsa20poly1305_NONCEBYTES=24</code> */
    public static final int crypto_secretbox_xsalsa20poly1305_NONCEBYTES = 24;
    /** Constant <code>crypto_secretbox_xsalsa20poly1305_ZEROBYTES=32</code> */
    public static final int crypto_secretbox_xsalsa20poly1305_ZEROBYTES = 32;
    /** Constant <code>crypto_secretbox_xsalsa20poly1305_BOXZEROBYTES=16</code> */
    public static final int crypto_secretbox_xsalsa20poly1305_BOXZEROBYTES = 16;

    /** Constant <code>crypto_secretbox_KEYBYTES=crypto_secretbox_xsalsa20poly1305_KEYBYTES</code> */
    public static final int crypto_secretbox_KEYBYTES = crypto_secretbox_xsalsa20poly1305_KEYBYTES;
    /** Constant <code>crypto_secretbox_NONCEBYTES=crypto_secretbox_xsalsa20poly1305_NONCEBYTES</code> */
    public static final int crypto_secretbox_NONCEBYTES = crypto_secretbox_xsalsa20poly1305_NONCEBYTES;
    /** Constant <code>crypto_secretbox_ZEROBYTES=crypto_secretbox_xsalsa20poly1305_ZEROBYTES</code> */
    public static final int crypto_secretbox_ZEROBYTES = crypto_secretbox_xsalsa20poly1305_ZEROBYTES;
    /** Constant <code>crypto_secretbox_BOXZEROBYTES=crypto_secretbox_xsalsa20poly1305_BOXZEROBYTES</code> */
    public static final int crypto_secretbox_BOXZEROBYTES = crypto_secretbox_xsalsa20poly1305_BOXZEROBYTES;


    /**
     * The crypto_secretbox function encrypts and authenticates a message m
     * using a secret key k and a nonce n. The crypto_secretbox function returns
     * the resulting ciphertext c. The function raises an exception if k.size()
     * is not crypto_secretbox_KEYBYTES. The function also raises an exception
     * if n.size() is not crypto_secretbox_NONCEBYTES.
     *
     * @param ac_out an array of byte.
     * @param m an array of byte.
     * @param n an array of byte.
     * @param k an array of byte.
     * @throws com.bendoerr.saltedmocha.CryptoException if any.
     */
    public static void crypto_secretbox(byte[] ac_out, byte[] m, byte[] n, byte[] k) throws CryptoException {
        crypto_secretbox_xsalsa20poly1305(ac_out, m, n, k);
    }

    /**
     * <p>crypto_secretbox.</p>
     *
     * @param m an array of byte.
     * @param n an array of byte.
     * @param k an array of byte.
     * @return an array of byte.
     * @throws com.bendoerr.saltedmocha.CryptoException if any.
     */
    public static byte[] crypto_secretbox(byte[] m, byte[] n, byte[] k) throws CryptoException {
        return crypto_secretbox_xsalsa20poly1305(m, n, k);
    }

    /**
     * <p>crypto_secretbox_xsalsa20poly1305.</p>
     *
     * @param m an array of byte.
     * @param n an array of byte.
     * @param k an array of byte.
     * @return an array of byte.
     * @throws com.bendoerr.saltedmocha.CryptoException if any.
     */
    public static byte[] crypto_secretbox_xsalsa20poly1305(byte[] m, byte[] n, byte[] k) throws CryptoException {
        byte[] ac_out = new byte[crypto_secretbox_xsalsa20poly1305_BOXZEROBYTES + m.length];
        crypto_secretbox_xsalsa20poly1305(ac_out, m, n, k);
        return ac_out;
    }

    /**
     * <p>crypto_secretbox_xsalsa20poly1305.</p>
     *
     * @param ac_out an array of byte.
     * @param m an array of byte.
     * @param n an array of byte.
     * @param k an array of byte.
     * @throws com.bendoerr.saltedmocha.CryptoException if any.
     */
    public static void crypto_secretbox_xsalsa20poly1305(byte[] ac_out, byte[] m, byte[] n, byte[] k) throws CryptoException {
        validateLength(k, crypto_secretbox_xsalsa20poly1305_KEYBYTES,
                "key", "crypto_secretbox_xsalsa20poly1305_KEYBYTES");

        validateLength(n, crypto_secretbox_xsalsa20poly1305_NONCEBYTES,
                "nonce", "crypto_secretbox_xsalsa20poly1305_NONCEBYTES");

        byte[] m2 = new byte[crypto_secretbox_xsalsa20poly1305_ZEROBYTES + m.length];
        checkedArrayCopy(m, 0, m2, crypto_secretbox_xsalsa20poly1305_ZEROBYTES, m.length);

        byte[] s = crypto_stream_xsalsa20_xor(m2, n, k);

        byte[] rs = copyOfRange(s, 0, crypto_secretbox_xsalsa20poly1305_ZEROBYTES);
        byte[] c = copyOfRange(s, crypto_secretbox_xsalsa20poly1305_ZEROBYTES, s.length);
        byte[] a = crypto_onetimeauth_poly1305(c, rs);


        checkedArrayCopy(a, 0, ac_out, 0, crypto_secretbox_xsalsa20poly1305_BOXZEROBYTES);
        checkedArrayCopy(c, 0, ac_out, crypto_secretbox_xsalsa20poly1305_BOXZEROBYTES, ac_out.length - crypto_secretbox_xsalsa20poly1305_BOXZEROBYTES);
    }

    /**
     * The crypto_secretbox_open function verifies and decrypts a ciphertext c
     * using a secret key k and a nonce n. The crypto_secretbox_open function
     * returns the resulting plaintext m.
     * <p>
     * If the ciphertext fails verification, crypto_secretbox_open raises an
     * exception. The function also raises an exception if k.size() is not
     * crypto_secretbox_KEYBYTES, or if n.size() is not
     * crypto_secretbox_NONCEBYTES.
     *
     * @param m_out an array of byte.
     * @param c an array of byte.
     * @param n an array of byte.
     * @param k an array of byte.
     * @throws com.bendoerr.saltedmocha.CryptoException if any.
     */
    public static void crypto_secretbox_open(byte[] m_out, byte[] c, byte[] n, byte[] k) throws CryptoException {
        crypto_secretbox_xsalsa20poly1305_open(m_out, c, n, k);
    }

    /**
     * <p>crypto_secretbox_open.</p>
     *
     * @param c an array of byte.
     * @param n an array of byte.
     * @param k an array of byte.
     * @return an array of byte.
     * @throws com.bendoerr.saltedmocha.CryptoException if any.
     */
    public static byte[] crypto_secretbox_open(byte[] c, byte[] n, byte[] k) throws CryptoException {
        return crypto_secretbox_xsalsa20poly1305_open(c, n, k);
    }

    /**
     * <p>crypto_secretbox_xsalsa20poly1305_open.</p>
     *
     * @param ac an array of byte.
     * @param n an array of byte.
     * @param k an array of byte.
     * @return an array of byte.
     * @throws com.bendoerr.saltedmocha.CryptoException if any.
     */
    public static byte[] crypto_secretbox_xsalsa20poly1305_open(byte[] ac, byte[] n, byte[] k) throws CryptoException {
        byte[] m_out = new byte[ac.length - crypto_secretbox_xsalsa20poly1305_BOXZEROBYTES];
        crypto_secretbox_xsalsa20poly1305_open(m_out, ac, n, k);
        return m_out;
    }

    /**
     * <p>crypto_secretbox_xsalsa20poly1305_open.</p>
     *
     * @param m_out an array of byte.
     * @param ac an array of byte.
     * @param n an array of byte.
     * @param k an array of byte.
     * @throws com.bendoerr.saltedmocha.CryptoException if any.
     */
    public static void crypto_secretbox_xsalsa20poly1305_open(byte[] m_out, byte[] ac, byte[] n, byte[] k) throws CryptoException {
        if (ac.length < 16)
            throw CryptoException.exceptionOf(new IllegalArgumentException("c is too small"));

        validateLength(k, crypto_secretbox_xsalsa20poly1305_KEYBYTES,
                "key", "crypto_secretbox_xsalsa20poly1305_KEYBYTES");

        validateLength(n, crypto_secretbox_xsalsa20poly1305_NONCEBYTES,
                "nonce", "crypto_secretbox_xsalsa20poly1305_NONCEBYTES");

        byte[] subkey = crypto_stream_xsalsa20(crypto_secretbox_xsalsa20poly1305_KEYBYTES, n, k);
        byte[] a = copyOfRange(ac, 0, crypto_secretbox_xsalsa20poly1305_BOXZEROBYTES);
        byte[] c = copyOfRange(ac, crypto_secretbox_xsalsa20poly1305_BOXZEROBYTES, ac.length);

        crypto_onetimeauth_poly1305_verify(a, c, subkey);

        byte[] c2 = new byte[crypto_secretbox_xsalsa20poly1305_ZEROBYTES + c.length];
        checkedArrayCopy(c, 0, c2, crypto_secretbox_xsalsa20poly1305_ZEROBYTES, c.length);

        byte[] m = crypto_stream_xsalsa20_xor(c2, n, k);
        checkedArrayCopy(m, crypto_secretbox_xsalsa20poly1305_ZEROBYTES, m_out, 0, m.length - crypto_secretbox_xsalsa20poly1305_ZEROBYTES);
    }
}
