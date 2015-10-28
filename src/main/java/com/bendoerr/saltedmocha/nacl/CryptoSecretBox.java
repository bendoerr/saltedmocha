package com.bendoerr.saltedmocha.nacl;

import static java.lang.System.arraycopy;
import static com.bendoerr.saltedmocha.nacl.CryptoStream.crypto_stream_xsalsa20;
import static com.bendoerr.saltedmocha.nacl.CryptoStream.crypto_stream_xsalsa20_xor;
import static org.bouncycastle.util.Arrays.copyOfRange;

public class CryptoSecretBox {

    public static final int crypto_secretbox_xsalsa20poly1305_KEYBYTES = 32;
    public static final int crypto_secretbox_xsalsa20poly1305_NONCEBYTES = 24;

    private static final int xsalsa20poly1305_ZEROBYTES = 32;
    private static final int xsalsa20poly1305_BOXZEROBYTES = 16;

    public static final int crypto_secretbox_KEYBYTES = crypto_secretbox_xsalsa20poly1305_KEYBYTES;
    public static final int crypto_secretbox_NONCEBYTES = crypto_secretbox_xsalsa20poly1305_NONCEBYTES;

    /**
     * The crypto_secretbox function encrypts and authenticates a message m
     * using a secret key k and a nonce n. The crypto_secretbox function returns
     * the resulting ciphertext c. The function raises an exception if k.size()
     * is not crypto_secretbox_KEYBYTES. The function also raises an exception
     * if n.size() is not crypto_secretbox_NONCEBYTES.
     */
    public static byte[] crypto_secretbox(byte[] m, byte[] n, byte[] k) {
        return crypto_secretbox_xsalsa20poly1305(m, n, k);
    }

    public static byte[] crypto_secretbox_xsalsa20poly1305(byte[] m, byte[] n, byte[] k) {
        if (k.length != crypto_secretbox_xsalsa20poly1305_KEYBYTES)
            throw new IllegalArgumentException("k must be crypto_secretbox_xsalsa20poly1305_KEYBYTES");

        if (n.length != crypto_secretbox_xsalsa20poly1305_NONCEBYTES)
            throw new IllegalArgumentException("n must be crypto_secretbox_xsalsa20poly1305_NONCEBYTES");

        byte[] m2 = new byte[xsalsa20poly1305_ZEROBYTES + m.length];
        arraycopy(m, 0, m2, xsalsa20poly1305_ZEROBYTES, m.length);

        byte[] s = crypto_stream_xsalsa20_xor(m2, n, k);

        byte[] rs = copyOfRange(s, 0, xsalsa20poly1305_ZEROBYTES);
        byte[] c = copyOfRange(s, xsalsa20poly1305_ZEROBYTES, s.length);
        byte[] a = CryptoOneTimeAuth.crypto_onetimeauth_poly1305(c, rs);


        byte[] ac = new byte[xsalsa20poly1305_BOXZEROBYTES + c.length];
        arraycopy(a, 0, ac, 0, xsalsa20poly1305_BOXZEROBYTES);
        arraycopy(c, 0, ac, xsalsa20poly1305_BOXZEROBYTES, c.length);

        return ac;
    }

    /**
     * The crypto_secretbox_open function verifies and decrypts a ciphertext c
     * using a secret key k and a nonce n. The crypto_secretbox_open function
     * returns the resulting plaintext m.
     *
     * If the ciphertext fails verification, crypto_secretbox_open raises an
     * exception. The function also raises an exception if k.size() is not
     * crypto_secretbox_KEYBYTES, or if n.size() is not
     * crypto_secretbox_NONCEBYTES.
     */
    public static byte[] crypto_secretbox_open(byte[] c, byte[] n, byte[] k) {
        return crypto_secretbox_xsalsa20poly1305_open(c, n , k);
    }

    public static byte[] crypto_secretbox_xsalsa20poly1305_open(byte[] ac, byte[] n, byte[] k) {
        if (ac.length < 16)
            throw new IllegalArgumentException("c is too small");

        if (k.length != crypto_secretbox_xsalsa20poly1305_KEYBYTES)
            throw new IllegalArgumentException("k must be crypto_secretbox_xsalsa20poly1305_KEYBYTES");

        if (n.length != crypto_secretbox_xsalsa20poly1305_NONCEBYTES)
            throw new IllegalArgumentException("n must be crypto_secretbox_xsalsa20poly1305_NONCEBYTES");

        byte[] subkey = crypto_stream_xsalsa20(crypto_secretbox_xsalsa20poly1305_KEYBYTES, n, k);
        byte[] a = copyOfRange(ac, 0, xsalsa20poly1305_BOXZEROBYTES);
        byte[] c = copyOfRange(ac, xsalsa20poly1305_BOXZEROBYTES, ac.length);

        CryptoOneTimeAuth.crypto_onetimeauth_poly1305_verify(a, c, subkey);

        byte[] c2 = new byte[xsalsa20poly1305_ZEROBYTES + c.length];
        arraycopy(c, 0, c2, xsalsa20poly1305_ZEROBYTES, c.length);
        byte[] m = crypto_stream_xsalsa20_xor(c2, n, k);

        byte[] m2 = new byte[m.length - xsalsa20poly1305_ZEROBYTES];
        arraycopy(m, xsalsa20poly1305_ZEROBYTES, m2, 0, m2.length);

        return m2;
    }
}
