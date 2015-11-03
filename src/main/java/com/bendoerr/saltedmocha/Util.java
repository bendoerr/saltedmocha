package com.bendoerr.saltedmocha;

import static com.bendoerr.saltedmocha.CryptoException.exceptionOf;
import static org.bouncycastle.util.Arrays.fill;

/**
 * <p>Util class.</p>
 */
public class Util {

    /**
     * Largest array that we could theoretically allocate without forcing an
     * <code>OutOfMemoryError</code>. It's still likely that you are going to
     * toss an <code>OutOfMemoryError</code> anytime you get near this since
     * you are limited by what is already on the heap.
     * <p>
     * Research suggest that on "modern" JVMs the upper bound is around
     * <code>Integer.MAX_VALUE - 2</code>. Anything past will instantly throw a
     * <code>OutOfMemoryError</code> regardless of available heap. In testing
     * a 4GB Xmx heap is needed to accommodate this.
     * <p>
     * There are several places in the libsodium code that do this sort of check
     * but I am really wondering if it's useful in Java.
     */
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

    private Util() {
    }

    /**
     * Wrapped call to <code>System.arraycopy()</code> that propagates the
     * <code>RuntimeException</code>s it throws as <code>CryptoException</code>s
     * allowing them to be handled as generic crypto failures.
     *
     * @param src    the source array.
     * @param srcPos starting position in the source array.
     * @param dst    the destination array.
     * @param dstPos starting position in the destination data.
     * @param len    the number of array elements to be copied.
     * @throws com.bendoerr.saltedmocha.CryptoException if the underlying call to
     *                                                  <code>System.arraycopy()</code> throws a
     *                                                  <code>RuntimeException</code>.
     * @see java.lang.System#arraycopy(Object, int, Object, int, int)
     */
    public static void checkedArrayCopy(Object src, int srcPos, Object dst, int dstPos, int len) throws CryptoException {
        try {
            System.arraycopy(src, srcPos, dst, dstPos, len);
        } catch (RuntimeException re) {
            throw exceptionOf(re);
        }
    }

    /**
     * Checks that the length of the <code>byte[]</code> is equal to the
     * <code>expected</code> value and returns. If the length is not equal then
     * it raises a <code>CryptoException</code> wrapping an
     * <code>IllegalArgumentException</code> and using the additional string
     * values to generate a human readable message.
     *
     * @param a            the array to check the length of.
     * @param expected     the expected length of the array.
     * @param expectedWhat a human-friendly name of the expected length.
     * @param what         a human-friendly name of the array being checked.
     * @param expectedWhat a human-friendly name of the expected length.
     * @throws com.bendoerr.saltedmocha.CryptoException if
     *                                                  <code>a.length != expected</code>.
     */
    public static void validateLength(byte[] a, int expected, String what, String expectedWhat) throws CryptoException {
        if (a.length != expected)
            throw exceptionOf(new IllegalArgumentException(
                    what + " length(" + a.length + ") is not " + expectedWhat + "(" + expected + ")"));
    }

    /**
     * Approximation of libsodium's <code>sodium_memzero</code>. For us in
     * Javaland it looks like <code>fill(array, (byte) 0)</code>
     *
     * @param array to zero out.
     * @see <a href="https://download.libsodium.org/doc/helpers/memory_management.html#zeroing-memory">Libsodium Zeroing Memory</a>
     */
    public static void java_memzero(byte[] array) {
        fill(array, (byte) 0);
    }

}
