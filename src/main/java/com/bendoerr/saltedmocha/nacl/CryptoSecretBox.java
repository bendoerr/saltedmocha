package com.bendoerr.saltedmocha.nacl;

import com.bendoerr.saltedmocha.CryptoException;

import static com.bendoerr.saltedmocha.Util.checkedArrayCopy;
import static com.bendoerr.saltedmocha.Util.validateLength;
import static com.bendoerr.saltedmocha.nacl.CryptoOneTimeAuth.crypto_onetimeauth_poly1305;
import static com.bendoerr.saltedmocha.nacl.CryptoOneTimeAuth.crypto_onetimeauth_poly1305_verify;
import static com.bendoerr.saltedmocha.nacl.CryptoStream.crypto_stream_xsalsa20;
import static com.bendoerr.saltedmocha.nacl.CryptoStream.crypto_stream_xsalsa20_xor;
import static org.bouncycastle.util.Arrays.copyOfRange;

public class CryptoSecretBox {

    public static final int crypto_secretbox_xsalsa20poly1305_KEYBYTES = 32;
    public static final int crypto_secretbox_xsalsa20poly1305_NONCEBYTES = 24;
    public static final int crypto_secretbox_xsalsa20poly1305_ZEROBYTES = 32;
    public static final int crypto_secretbox_xsalsa20poly1305_BOXZEROBYTES = 16;

    public static final int crypto_secretbox_KEYBYTES = crypto_secretbox_xsalsa20poly1305_KEYBYTES;
    public static final int crypto_secretbox_NONCEBYTES = crypto_secretbox_xsalsa20poly1305_NONCEBYTES;
    public static final int crypto_secretbox_ZEROBYTES = crypto_secretbox_xsalsa20poly1305_ZEROBYTES;
    public static final int crypto_secretbox_BOXZEROBYTES = crypto_secretbox_xsalsa20poly1305_BOXZEROBYTES;


    /**
     * The crypto_secretbox function encrypts and authenticates a message m
     * using a secret key k and a nonce n. The crypto_secretbox function returns
     * the resulting ciphertext c. The function raises an exception if k.size()
     * is not crypto_secretbox_KEYBYTES. The function also raises an exception
     * if n.size() is not crypto_secretbox_NONCEBYTES.
     */
    public static void crypto_secretbox(byte[] ac_out, byte[] m, byte[] n, byte[] k) throws CryptoException {
        crypto_secretbox_xsalsa20poly1305(ac_out, m, n, k);
    }

    public static byte[] crypto_secretbox(byte[] m, byte[] n, byte[] k) throws CryptoException {
        return crypto_secretbox_xsalsa20poly1305(m, n, k);
    }

    public static byte[] crypto_secretbox_xsalsa20poly1305(byte[] m, byte[] n, byte[] k) throws CryptoException {
        byte[] ac_out = new byte[crypto_secretbox_xsalsa20poly1305_BOXZEROBYTES + m.length];
        crypto_secretbox_xsalsa20poly1305(ac_out, m, n, k);
        return ac_out;
    }

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
     */
    public static void crypto_secretbox_open(byte[] m_out, byte[] c, byte[] n, byte[] k) throws CryptoException {
        crypto_secretbox_xsalsa20poly1305_open(m_out, c, n, k);
    }

    public static byte[] crypto_secretbox_open(byte[] c, byte[] n, byte[] k) throws CryptoException {
        return crypto_secretbox_xsalsa20poly1305_open(c, n, k);
    }

    public static byte[] crypto_secretbox_xsalsa20poly1305_open(byte[] ac, byte[] n, byte[] k) throws CryptoException {
        byte[] m_out = new byte[ac.length - crypto_secretbox_xsalsa20poly1305_BOXZEROBYTES];
        crypto_secretbox_xsalsa20poly1305_open(m_out, ac, n, k);
        return m_out;
    }

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
