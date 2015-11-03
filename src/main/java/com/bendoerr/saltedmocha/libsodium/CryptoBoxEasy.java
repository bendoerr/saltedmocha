package com.bendoerr.saltedmocha.libsodium;

import com.bendoerr.saltedmocha.CryptoException;
import com.bendoerr.saltedmocha.nacl.CryptoBox;
import com.bendoerr.saltedmocha.nacl.CryptoOneTimeAuth;

import static com.bendoerr.saltedmocha.Util.MAX_ARRAY_SIZE;
import static com.bendoerr.saltedmocha.libsodium.CryptoSecretBoxEasy.crypto_secretbox_detached;
import static com.bendoerr.saltedmocha.libsodium.CryptoSecretBoxEasy.crypto_secretbox_open_detached;
import static com.bendoerr.saltedmocha.nacl.CryptoBox.*;

/**
 * <p>CryptoBoxEasy class.</p>
 */
public class CryptoBoxEasy {

    /** Constant <code>crypto_box_PUBLICKEYBYTES=CryptoBox.crypto_box_PUBLICKEYBYTES</code> */
    public static final int crypto_box_PUBLICKEYBYTES = CryptoBox.crypto_box_PUBLICKEYBYTES;
    /** Constant <code>crypto_box_SECRETKEYBYTES=CryptoBox.crypto_box_SECRETKEYBYTES</code> */
    public static final int crypto_box_SECRETKEYBYTES = CryptoBox.crypto_box_SECRETKEYBYTES;
    /** Constant <code>crypto_box_MACBYTES=CryptoOneTimeAuth.crypto_onetimeauth_BYTES</code> */
    public static final int crypto_box_MACBYTES = CryptoOneTimeAuth.crypto_onetimeauth_BYTES;
    /** Constant <code>crypto_box_NONCEBYTES=CryptoBox.crypto_box_NONCEBYTES</code> */
    public static final int crypto_box_NONCEBYTES = CryptoBox.crypto_box_NONCEBYTES;
    /** Constant <code>crypto_box_SEEDBYTES=0</code> */
    public static final int crypto_box_SEEDBYTES = 0;
    /** Constant <code>crypto_box_BEFORENMBYTES=CryptoBox.crypto_box_BEFORENM</code> */
    public static final int crypto_box_BEFORENMBYTES = CryptoBox.crypto_box_BEFORENM;

    //    int
    //    crypto_box_detached_afternm(unsigned char *c, unsigned char *mac,
    //                                const unsigned char *m, unsigned long long mlen,
    //                                const unsigned char *n, const unsigned char *k)
    //    {
    //        return crypto_secretbox_detached(c, mac, m, mlen, n, k);
    //    }

    /**
     * <p>crypto_box_detached_afternm.</p>
     *
     * @param c_out an array of byte.
     * @param mac_out an array of byte.
     * @param mac_out an array of byte.
     * @param m an array of byte.
     * @param n an array of byte.
     * @param k an array of byte.
     * @throws com.bendoerr.saltedmocha.CryptoException if any.
     */
    public static void crypto_box_detached_afternm(final byte[] c_out, final byte[] mac_out,
                                                   final byte[] m, final byte[] n,
                                                   final byte[] k) throws CryptoException {
        crypto_secretbox_detached(c_out, mac_out, m, n, k);
    }

    //    int
    //    crypto_box_detached(unsigned char *c, unsigned char *mac,
    //                        const unsigned char *m, unsigned long long mlen,
    //                        const unsigned char *n, const unsigned char *pk,
    //                        const unsigned char *sk)
    //    {
    //        unsigned char k[crypto_box_BEFORENMBYTES];
    //        int           ret;
    //
    //        (void) sizeof(int[crypto_box_BEFORENMBYTES >=
    //            crypto_secretbox_KEYBYTES ? 1 : -1]);
    //        crypto_box_beforenm(k, pk, sk);
    //        ret = crypto_box_detached_afternm(c, mac, m, mlen, n, k);
    //        sodium_memzero(k, sizeof k);
    //
    //        return ret;
    //    }

    /**
     * <p>crypto_box_detatched.</p>
     *
     * @param c_out an array of byte.
     * @param mac_out an array of byte.
     * @param mac_out an array of byte.
     * @param m an array of byte.
     * @param n an array of byte.
     * @param pk an array of byte.
     * @param sk an array of byte.
     * @throws com.bendoerr.saltedmocha.CryptoException if any.
     */
    public static void crypto_box_detatched(final byte[] c_out, final byte[] mac_out,
                                            final byte[] m, final byte[] n, final byte[] pk,
                                            final byte[] sk) throws CryptoException {
        crypto_box_detached_afternm(c_out, mac_out, m, n,
                crypto_box_beforenm(pk, sk));
    }

    //    int
    //    crypto_box_easy_afternm(unsigned char *c, const unsigned char *m,
    //                            unsigned long long mlen, const unsigned char *n,
    //                            const unsigned char *k)
    //    {
    //        if (mlen > SIZE_MAX - crypto_box_MACBYTES) {
    //            return -1;
    //        }
    //        return crypto_box_detached_afternm(c + crypto_box_MACBYTES, c, m, mlen, n,
    //                k);
    //    }

    /**
     * <p>crypto_box_easy_afternm.</p>
     *
     * @param c_out an array of byte.
     * @param m an array of byte.
     * @param n an array of byte.
     * @param k an array of byte.
     * @throws com.bendoerr.saltedmocha.CryptoException if any.
     */
    public static void crypto_box_easy_afternm(final byte[] c_out, final byte[] m,
                                               final byte[] n, final byte[] k) throws CryptoException {
        if (m.length > MAX_ARRAY_SIZE - crypto_box_MACBYTES)
            throw new CryptoException("m is too big");

        crypto_box_afternm(c_out, m, n, k);
    }

    //    int
    //    crypto_box_easy(unsigned char *c, const unsigned char *m,
    //                    unsigned long long mlen, const unsigned char *n,
    //                    const unsigned char *pk, const unsigned char *sk)
    //    {
    //        if (mlen > SIZE_MAX - crypto_box_MACBYTES) {
    //            return -1;
    //        }
    //        return crypto_box_detached(c + crypto_box_MACBYTES, c, m, mlen, n,
    //                pk, sk);
    //    }

    /**
     * <p>crypto_box_easy.</p>
     *
     * @param c_out an array of byte.
     * @param m an array of byte.
     * @param n an array of byte.
     * @param pk an array of byte.
     * @param sk an array of byte.
     * @throws com.bendoerr.saltedmocha.CryptoException if any.
     */
    public static void crypto_box_easy(final byte[] c_out, final byte[] m, final byte[] n,
                                       final byte[] pk, final byte[] sk) throws CryptoException {
        if (m.length > MAX_ARRAY_SIZE - crypto_box_MACBYTES)
            throw new CryptoException("m is too big");

        crypto_box(c_out, m, n, pk, sk);
    }

    //    int
    //    crypto_box_open_detached_afternm(unsigned char *m, const unsigned char *c,
    //                                     const unsigned char *mac,
    //                                     unsigned long long clen, const unsigned char *n,
    //                                     const unsigned char *k)
    //    {
    //        return crypto_secretbox_open_detached(m, c, mac, clen, n, k);
    //    }

    /**
     * <p>crypto_box_open_detached_afternm.</p>
     *
     * @param m_out an array of byte.
     * @param c an array of byte.
     * @param mac an array of byte.
     * @param n an array of byte.
     * @param k an array of byte.
     * @throws com.bendoerr.saltedmocha.CryptoException if any.
     */
    public static void crypto_box_open_detached_afternm(final byte[] m_out, final byte[] c,
                                                        final byte[] mac, final byte[] n,
                                                        final byte[] k) throws CryptoException {
        crypto_secretbox_open_detached(m_out, c, mac, n, k);
    }

    //    int
    //    crypto_box_open_detached(unsigned char *m, const unsigned char *c,
    //                             const unsigned char *mac,
    //                             unsigned long long clen, const unsigned char *n,
    //                             const unsigned char *pk, const unsigned char *sk)
    //    {
    //        unsigned char k[crypto_box_BEFORENMBYTES];
    //        int           ret;
    //
    //        crypto_box_beforenm(k, pk, sk);
    //        ret = crypto_box_open_detached_afternm(m, c, mac, clen, n, k);
    //        sodium_memzero(k, sizeof k);
    //
    //        return ret;
    //    }

    /**
     * <p>crypto_box_open_detached.</p>
     *
     * @param m_out an array of byte.
     * @param c an array of byte.
     * @param mac an array of byte.
     * @param n an array of byte.
     * @param pk an array of byte.
     * @param sk an array of byte.
     * @throws com.bendoerr.saltedmocha.CryptoException if any.
     */
    public static void crypto_box_open_detached(final byte[] m_out, final byte[] c,
                                                final byte[] mac, final byte[] n,
                                                final byte[] pk, final byte[] sk) throws CryptoException {
        crypto_box_open_detached_afternm(m_out, c, mac, n,
                crypto_box_beforenm(pk, sk));
    }

    //    int
    //    crypto_box_open_easy_afternm(unsigned char *m, const unsigned char *c,
    //                                 unsigned long long clen, const unsigned char *n,
    //                                 const unsigned char *k)
    //    {
    //        if (clen < crypto_box_MACBYTES) {
    //            return -1;
    //        }
    //        return crypto_box_open_detached_afternm(m, c + crypto_box_MACBYTES, c,
    //                clen - crypto_box_MACBYTES,
    //                n, k);
    //    }

    /**
     * <p>crypto_box_open_easy_afternm.</p>
     *
     * @param m_out an array of byte.
     * @param c an array of byte.
     * @param n an array of byte.
     * @param k an array of byte.
     * @throws com.bendoerr.saltedmocha.CryptoException if any.
     */
    public static void crypto_box_open_easy_afternm(final byte[] m_out, final byte[] c,
                                                    final byte[] n, final byte[] k) throws CryptoException {
        crypto_box_open_afternm(m_out, c, n, k);
    }

    //    int
    //    crypto_box_open_easy(unsigned char *m, const unsigned char *c,
    //                         unsigned long long clen, const unsigned char *n,
    //                         const unsigned char *pk, const unsigned char *sk)
    //    {
    //        if (clen < crypto_box_MACBYTES) {
    //            return -1;
    //        }
    //        return crypto_box_open_detached(m, c + crypto_box_MACBYTES, c,
    //                clen - crypto_box_MACBYTES,
    //                n, pk, sk);
    //    }

    /**
     * <p>crypto_box_open_easy.</p>
     *
     * @param m_out an array of byte.
     * @param c an array of byte.
     * @param n an array of byte.
     * @param pk an array of byte.
     * @param sk an array of byte.
     * @throws com.bendoerr.saltedmocha.CryptoException if any.
     */
    public static void crypto_box_open_easy(final byte[] m_out, final byte[] c, final byte[] n,
                                            final byte[] pk, final byte[] sk) throws CryptoException {
        crypto_box_open(m_out, c, n, pk, sk);
    }
}
