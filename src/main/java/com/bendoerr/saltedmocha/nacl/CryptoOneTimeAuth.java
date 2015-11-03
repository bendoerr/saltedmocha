package com.bendoerr.saltedmocha.nacl;

import com.bendoerr.saltedmocha.CryptoException;
import org.bouncycastle.crypto.macs.Poly1305;
import org.bouncycastle.crypto.params.KeyParameter;

import static com.bendoerr.saltedmocha.CryptoException.exception;
import static com.bendoerr.saltedmocha.CryptoException.exceptionOf;
import static com.bendoerr.saltedmocha.Util.checkedArrayCopy;
import static com.bendoerr.saltedmocha.Util.validateLength;
import static org.bouncycastle.crypto.generators.Poly1305KeyGenerator.clamp;
import static org.bouncycastle.util.Arrays.constantTimeAreEqual;

/**
 * <p>CryptoOneTimeAuth class.</p>
 */
public class CryptoOneTimeAuth {

    /** Constant <code>crypto_onetimeauth_BYTES=16</code> */
    public static final int crypto_onetimeauth_BYTES = 16;
    /** Constant <code>crypto_onetimeauth_KEYBYTES=32</code> */
    public static final int crypto_onetimeauth_KEYBYTES = 32;

    /** Constant <code>crypto_onetimeauth_poly1305_BYTES=16</code> */
    public static final int crypto_onetimeauth_poly1305_BYTES = 16;
    /** Constant <code>crypto_onetimeauth_poly1305_KEYBYTES=32</code> */
    public static final int crypto_onetimeauth_poly1305_KEYBYTES = 32;

    /**
     * The crypto_onetimeauth function authenticates a message m using a secret
     * key k, and returns an authenticator a. The authenticator length is always
     * crypto_onetimeauth_BYTES. The function raises an exception if k.length is
     * not crypto_onetimeauth_KEYBYTES.
     *
     * @param a_out an array of byte.
     * @param m an array of byte.
     * @param k an array of byte.
     * @throws com.bendoerr.saltedmocha.CryptoException if any.
     */
    public static void crypto_onetimeauth(byte[] a_out, byte[] m, byte[] k) throws CryptoException {
        crypto_onetimeauth_poly1305(a_out, m, k);
    }

    /**
     * <p>crypto_onetimeauth.</p>
     *
     * @param m an array of byte.
     * @param k an array of byte.
     * @return an array of byte.
     * @throws com.bendoerr.saltedmocha.CryptoException if any.
     */
    public static byte[] crypto_onetimeauth(byte[] m, byte[] k) throws CryptoException {
        return crypto_onetimeauth_poly1305(m, k);
    }

    /**
     * <p>crypto_onetimeauth_poly1305.</p>
     *
     * @param m an array of byte.
     * @param k an array of byte.
     * @return an array of byte.
     * @throws com.bendoerr.saltedmocha.CryptoException if any.
     */
    public static byte[] crypto_onetimeauth_poly1305(byte[] m, byte[] k) throws CryptoException {
        byte[] a_out = new byte[crypto_onetimeauth_poly1305_BYTES];
        crypto_onetimeauth_poly1305(a_out, m, k);
        return a_out;
    }

    /**
     * <p>crypto_onetimeauth_poly1305.</p>
     *
     * @param a_out an array of byte.
     * @param m an array of byte.
     * @param k an array of byte.
     * @throws com.bendoerr.saltedmocha.CryptoException if any.
     */
    public static void crypto_onetimeauth_poly1305(byte[] a_out, byte[] m, byte[] k) throws CryptoException {
        validateLength(k, crypto_onetimeauth_poly1305_KEYBYTES,
                "key", "crypto_onetimeauth_poly1305_KEYBYTES");

        // BouncyCastle has a flipped key layout.
        byte[] kf = new byte[crypto_onetimeauth_poly1305_KEYBYTES];
        checkedArrayCopy(k, 16, kf, 0, 16);
        checkedArrayCopy(k, 0, kf, 16, 16);

        try {
            clamp(kf); // ClampP
            Poly1305 mac = new Poly1305();
            mac.init(new KeyParameter(kf));
            mac.update(m, 0, m.length);
            mac.doFinal(a_out, 0);
        } catch (RuntimeException re) {
            throw exceptionOf(re);
        }
    }

    /**
     * This function checks that k.size() is crypto_onetimeauth_KEYBYTES;
     * a.size() is crypto_onetimeauth_BYTES;
     * and a is a correct authenticator of a message m under the secret key k.
     * If any of these checks fail, the function raises an exception.
     *
     * @param a an array of byte.
     * @param m an array of byte.
     * @param k an array of byte.
     * @throws com.bendoerr.saltedmocha.CryptoException if any.
     */
    public static void crypto_onetimeauth_verify(byte[] a, byte[] m, byte[] k) throws CryptoException {
        crypto_onetimeauth_poly1305_verify(a, m, k);
    }

    /**
     * <p>crypto_onetimeauth_poly1305_verify.</p>
     *
     * @param a an array of byte.
     * @param m an array of byte.
     * @param k an array of byte.
     * @throws com.bendoerr.saltedmocha.CryptoException if any.
     */
    public static void crypto_onetimeauth_poly1305_verify(byte[] a, byte[] m, byte[] k) throws CryptoException {
        validateLength(k, crypto_onetimeauth_poly1305_KEYBYTES,
                "key", "crypto_onetimeauth_poly1305_KEYBYTES");

        validateLength(a, crypto_onetimeauth_poly1305_BYTES,
                "auth", "crypto_onetimeauth_poly1305_BYTES");

        byte[] a2 = crypto_onetimeauth_poly1305(m, k);
        if (!constantTimeAreEqual(a, a2))
            throw exception("failed to verify");
    }
}
