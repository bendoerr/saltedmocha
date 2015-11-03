package com.bendoerr.saltedmocha.nacl;

import com.bendoerr.saltedmocha.CryptoException;

import static com.bendoerr.saltedmocha.CryptoException.exceptionOf;
import static com.bendoerr.saltedmocha.Util.checkedArrayCopy;
import static com.bendoerr.saltedmocha.Util.validateLength;

/**
 * <p>CryptoCore class.</p>
 */
public class CryptoCore {

    /**
     * Constant <code>crypto_core_hsalsa_INPUTBYTES=16</code>
     */
    public static int crypto_core_hsalsa_INPUTBYTES = 16;
    /**
     * Constant <code>crypto_core_hsalsa_OUTPUTBYTES=32</code>
     */
    public static int crypto_core_hsalsa_OUTPUTBYTES = 32;
    /**
     * Constant <code>crypto_core_hsalsa_KEYBYTES=32</code>
     */
    public static int crypto_core_hsalsa_KEYBYTES = 32;
    /**
     * Constant <code>crypto_core_salsa_INPUTBYTES=16</code>
     */
    public static int crypto_core_salsa_INPUTBYTES = 16;
    /**
     * Constant <code>crypto_core_salsa_OUTPUTBYTES=64</code>
     */
    public static int crypto_core_salsa_OUTPUTBYTES = 64;
    /**
     * Constant <code>crypto_core_salsa_KEYBYTES=32</code>
     */
    public static int crypto_core_salsa_KEYBYTES = 32;
    private CryptoCore() {
    }

    /**
     * <p>crypto_core_hsalsa20.</p>
     *
     * @param out an array of byte.
     * @param in  an array of byte.
     * @param k   an array of byte.
     * @throws com.bendoerr.saltedmocha.CryptoException if any.
     */
    public static void crypto_core_hsalsa20(byte[] out, byte[] in, byte[] k) throws CryptoException {
        checkedArrayCopy(
                crypto_core_hsalsa20(in, k), 0,
                out, 0, crypto_core_hsalsa_OUTPUTBYTES);
    }

    /**
     * <p>crypto_core_hsalsa20.</p>
     *
     * @param in an array of byte.
     * @param k  an array of byte.
     * @return an array of byte.
     * @throws com.bendoerr.saltedmocha.CryptoException if any.
     */
    public static byte[] crypto_core_hsalsa20(byte[] in, byte[] k) throws CryptoException {
        validateLength(k, crypto_core_hsalsa_KEYBYTES,
                "key", "crypto_core_hsalsa_KEYBYTES");

        try {
            return new CryptoStream.Salsa20Cipher(in, k, true).core();
        } catch (RuntimeException re) {
            throw exceptionOf(re);
        }
    }

    /**
     * <p>crypto_core_salsa20.</p>
     *
     * @param out an array of byte.
     * @param in  an array of byte.
     * @param k   an array of byte.
     * @throws com.bendoerr.saltedmocha.CryptoException if any.
     */
    public static void crypto_core_salsa20(byte[] out, byte[] in, byte[] k) throws CryptoException {
        checkedArrayCopy(
                crypto_core_salsa20(in, k), 0,
                out, 0, crypto_core_salsa_OUTPUTBYTES);
    }

    /**
     * <p>crypto_core_salsa20.</p>
     *
     * @param in an array of byte.
     * @param k  an array of byte.
     * @return an array of byte.
     * @throws com.bendoerr.saltedmocha.CryptoException if any.
     */
    public static byte[] crypto_core_salsa20(byte[] in, byte[] k) throws CryptoException {
        validateLength(k, crypto_core_salsa_KEYBYTES,
                "key", "crypto_core_salsa_KEYBYTES");

        try {
            return new CryptoStream.Salsa20Cipher(in, k).core();
        } catch (RuntimeException re) {
            throw exceptionOf(re);
        }
    }
}
