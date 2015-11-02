package com.bendoerr.saltedmocha;

import static com.bendoerr.saltedmocha.CryptoException.exceptionOf;

public class Util {

    public static final int MAX_ARRAY_SIZE;

    static {
        int max = Integer.MAX_VALUE - 2;
        try {
            byte[] bytes = new byte[max];
        } catch (java.lang.OutOfMemoryError oom) {
            // Probably OK. Need to test on 32bit JVM.
            // Reports say it's somewhere around 1.1 billion.
            max = Integer.MAX_VALUE / 2;
        }
        MAX_ARRAY_SIZE = max;
    }

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
