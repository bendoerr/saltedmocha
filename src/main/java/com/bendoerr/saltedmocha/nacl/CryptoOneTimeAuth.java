package com.bendoerr.saltedmocha.nacl;

import org.bouncycastle.crypto.macs.Poly1305;
import org.bouncycastle.crypto.params.KeyParameter;

import static java.lang.System.arraycopy;
import static org.bouncycastle.crypto.generators.Poly1305KeyGenerator.clamp;
import static org.bouncycastle.util.Arrays.constantTimeAreEqual;

public class CryptoOneTimeAuth {

    public static final int crypto_onetimeauth_BYTES = 16;
    public static final int crypto_onetimeauth_KEYBYTES = 32;

    public static final int crypto_onetimeauth_poly1305_BYTES = 16;
    public static final int crypto_onetimeauth_poly1305_KEYBYTES = 32;

    /**
     * The crypto_onetimeauth function authenticates a message m using a secret
     * key k, and returns an authenticator a. The authenticator length is always
     * crypto_onetimeauth_BYTES. The function raises an exception if k.length is
     * not crypto_onetimeauth_KEYBYTES.
     */
    public static byte[] crypto_onetimeauth(byte[] m, byte[] k) {
        return crypto_onetimeauth_poly1305(m, k);
    }

    public static byte[] crypto_onetimeauth_poly1305(byte[] m, byte[] k) {
        if (k.length != crypto_onetimeauth_poly1305_KEYBYTES)
            throw new IllegalArgumentException(
                    "k.length is not crypto_onetimeauth_KEYBYTES.");

        // BouncyCastle has a flipped key layout.
        byte[] kf = new byte[crypto_onetimeauth_poly1305_KEYBYTES];
        arraycopy(k, 16, kf, 0, 16);
        arraycopy(k, 0, kf, 16, 16);

        byte[] a = new byte[crypto_onetimeauth_poly1305_BYTES];

        clamp(kf); // ClampP

        Poly1305 mac = new Poly1305();
        mac.init(new KeyParameter(kf));
        mac.update(m, 0, m.length);
        mac.doFinal(a, 0);

        return a;
    }

    /**
     * This function checks that k.size() is crypto_onetimeauth_KEYBYTES;
     * a.size() is crypto_onetimeauth_BYTES;
     * and a is a correct authenticator of a message m under the secret key k.
     * If any of these checks fail, the function raises an exception.
     */
    public static void crypto_onetimeauth_verify(byte[] a, byte[] m, byte[] k) {
        crypto_onetimeauth_poly1305_verify(a, m, k);
    }

    public static void crypto_onetimeauth_poly1305_verify(byte[] a, byte[] m, byte[] k) {
        if (k.length != crypto_onetimeauth_poly1305_KEYBYTES)
            throw new IllegalArgumentException(
                    "k.length is not crypto_onetimeauth_KEYBYTES.");

        if (a.length != crypto_onetimeauth_poly1305_BYTES)
            throw new IllegalArgumentException(
                    "a.length is not crypto_onetimeauth_BYTES");

        byte[] a2 = crypto_onetimeauth_poly1305(m, k);
        if (!constantTimeAreEqual(a, a2))
            throw new CryptoOneTimeAuthException("failed to verify");
    }

    public static class CryptoOneTimeAuthException extends RuntimeException {
        public CryptoOneTimeAuthException(String message) {
            super(message);
        }
    }

    ;
}
