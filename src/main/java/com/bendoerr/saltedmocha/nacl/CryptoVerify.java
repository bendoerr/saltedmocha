package com.bendoerr.saltedmocha.nacl;

import static org.bouncycastle.util.Arrays.constantTimeAreEqual;

/**
 * <p>CryptoVerify class.</p>
 */
public class CryptoVerify {

    /**
     * <p>crypto_verify_16.</p>
     *
     * @param x an array of byte.
     * @param y an array of byte.
     * @return a boolean.
     */
    public static boolean crypto_verify_16(byte[] x, byte[] y) {
        return constantTimeAreEqual(x, y);
    }

    /**
     * <p>crypto_verify_32.</p>
     *
     * @param x an array of byte.
     * @param y an array of byte.
     * @return a boolean.
     */
    public static boolean crypto_verify_32(byte[] x, byte[] y) {
        return constantTimeAreEqual(x, y);
    }
}
