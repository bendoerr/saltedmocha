package com.bendoerr.saltedmocha.nacl;

import static org.bouncycastle.util.Arrays.constantTimeAreEqual;

public class CryptoVerify {

    public static boolean crypto_verify_16(byte[] x, byte[] y) {
        return constantTimeAreEqual(x, y);
    }

    public static boolean crypto_verify_32(byte[] x, byte[] y) {
        return constantTimeAreEqual(x, y);
    }
}
