package com.bendoerr.saltedmocha.libsodium;

import com.bendoerr.saltedmocha.CryptoException;
import com.bendoerr.saltedmocha.Util;
import com.bendoerr.saltedmocha.nacl.CryptoOneTimeAuth;
import com.bendoerr.saltedmocha.nacl.CryptoSecretBox;

import static com.bendoerr.saltedmocha.Util.checkedArrayCopy;
import static com.bendoerr.saltedmocha.nacl.CryptoSecretBox.crypto_secretbox;
import static com.bendoerr.saltedmocha.nacl.CryptoSecretBox.crypto_secretbox_open;
import static org.bouncycastle.util.Arrays.concatenate;

/**
 * <p>CryptoSecretBoxEasy class.</p>
 */
public class CryptoSecretBoxEasy {

    /** Constant <code>crypto_secretbox_KEYBYTES=CryptoSecretBox.crypto_secretbox_KEYBYTES</code> */
    public static final int crypto_secretbox_KEYBYTES = CryptoSecretBox.crypto_secretbox_KEYBYTES;
    /** Constant <code>crypto_secretbox_MACBYTES=CryptoOneTimeAuth.crypto_onetimeauth_BYTES</code> */
    public static final int crypto_secretbox_MACBYTES = CryptoOneTimeAuth.crypto_onetimeauth_BYTES;
    /** Constant <code>crypto_secretbox_NONCEBYTES=CryptoSecretBox.crypto_secretbox_NONCEBYTES</code> */
    public static final int crypto_secretbox_NONCEBYTES = CryptoSecretBox.crypto_secretbox_NONCEBYTES;

    //    int
    //    crypto_secretbox_detached(unsigned char *c, unsigned char *mac,
    //                              const unsigned char *m,
    //                              unsigned long long mlen, const unsigned char *n,
    //                              const unsigned char *k)
    /**
     * <p>crypto_secretbox_detached.</p>
     *
     * @param c_out an array of byte.
     * @param mac_out an array of byte.
     * @param mac_out an array of byte.
     * @param m an array of byte.
     * @param n an array of byte.
     * @param k an array of byte.
     * @throws com.bendoerr.saltedmocha.CryptoException if any.
     */
    public static void crypto_secretbox_detached(final byte[] c_out, final byte[] mac_out,
                                                 final byte[] m, final byte[] n,
                                                 final byte[] k) throws CryptoException {

        if (m.length > Util.MAX_ARRAY_SIZE - crypto_secretbox_MACBYTES)
            throw new CryptoException("m is too big");

        byte[] tmp = crypto_secretbox(m, n, k);
        checkedArrayCopy(tmp, 0, mac_out, 0, crypto_secretbox_MACBYTES);
        checkedArrayCopy(tmp, crypto_secretbox_MACBYTES, c_out, 0, tmp.length - crypto_secretbox_MACBYTES);
    }

    //    int
    //    crypto_secretbox_easy(unsigned char *c, const unsigned char *m,
    //                          unsigned long long mlen, const unsigned char *n,
    //                          const unsigned char *k)
    /**
     * <p>crypto_secretbox_easy.</p>
     *
     * @param c_out an array of byte.
     * @param m an array of byte.
     * @param n an array of byte.
     * @param k an array of byte.
     * @throws com.bendoerr.saltedmocha.CryptoException if any.
     */
    public static void crypto_secretbox_easy(final byte[] c_out, final byte[] m,
                                             final byte[] n, final byte[] k) throws CryptoException {
        if (m.length > Util.MAX_ARRAY_SIZE - crypto_secretbox_MACBYTES)
            throw new CryptoException("m is too big");

        crypto_secretbox(c_out, m, n, k);
    }

    //    int
    //    crypto_secretbox_open_detached(unsigned char *m, const unsigned char *c,
    //                                   const unsigned char *mac,
    //                                   unsigned long long clen,
    //                                   const unsigned char *n,
    //                                   const unsigned char *k)
    /**
     * <p>crypto_secretbox_open_detached.</p>
     *
     * @param m_out an array of byte.
     * @param c an array of byte.
     * @param mac an array of byte.
     * @param n an array of byte.
     * @param k an array of byte.
     * @throws com.bendoerr.saltedmocha.CryptoException if any.
     */
    public static void crypto_secretbox_open_detached(final byte[] m_out, final byte[] c,
                                                      final byte[] mac, final byte[] n,
                                                      final byte[] k) throws CryptoException {
        crypto_secretbox_open(m_out, concatenate(mac, c), n, k);
    }

    //    int
    //    crypto_secretbox_open_easy(unsigned char *m, const unsigned char *c,
    //                               unsigned long long clen, const unsigned char *n,
    //                               const unsigned char *k)
    /**
     * <p>crypto_secretbox_open_easy.</p>
     *
     * @param m_out an array of byte.
     * @param c an array of byte.
     * @param n an array of byte.
     * @param k an array of byte.
     * @throws com.bendoerr.saltedmocha.CryptoException if any.
     */
    public static void crypto_secretbox_open_easy(final byte[] m_out, final byte[] c,
                                                  final byte[] n, final byte[] k) throws CryptoException {
        crypto_secretbox_open(m_out, c, n, k);
    }
}
