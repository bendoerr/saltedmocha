package com.bendoerr.saltedmocha;

import static com.bendoerr.saltedmocha.CryptoException.exceptionOf;

public class Util {

    public static void checkedArrayCopy(Object src, int srcPos, Object dst, int dstPos, int len) throws CryptoException {
        try {
            System.arraycopy(src, srcPos, dst, dstPos, len);
        } catch (RuntimeException re) {
            throw exceptionOf(re);
        }
    }

    public static void validateLength(byte[] a, int expected, String what, String expectedWhat) throws CryptoException {
        if (a.length != expected)
            throw exceptionOf(new IllegalArgumentException(
                    what + " length(" + a.length + ") is not " + expectedWhat + "(" + expected + ")"));
    }

}
