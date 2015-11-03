package com.bendoerr.saltedmocha.nacl;

import com.bendoerr.saltedmocha.CryptoException;

import static com.bendoerr.saltedmocha.CryptoException.exceptionOf;
import static com.bendoerr.saltedmocha.Util.checkedArrayCopy;
import static com.bendoerr.saltedmocha.Util.validateLength;

public class CryptoCore {

    public static int crypto_core_hsalsa_INPUTBYTES = 16;
    public static int crypto_core_hsalsa_OUTPUTBYTES = 32;
    public static int crypto_core_hsalsa_KEYBYTES = 32;

    public static int crypto_core_salsa_INPUTBYTES = 16;
    public static int crypto_core_salsa_OUTPUTBYTES = 64;
    public static int crypto_core_salsa_KEYBYTES = 32;

    public static void crypto_core_hsalsa20(byte[] out, byte[] in, byte[] k) throws CryptoException {
        checkedArrayCopy(
                crypto_core_hsalsa20(in, k), 0,
                out, 0, crypto_core_hsalsa_OUTPUTBYTES);
    }

    public static byte[] crypto_core_hsalsa20(byte[] in, byte[] k) throws CryptoException {
        validateLength(k, crypto_core_hsalsa_KEYBYTES,
                "key", "crypto_core_hsalsa_KEYBYTES");

        try {
            return new CryptoStream.Salsa20Cipher(in, k, true).core();
        } catch (RuntimeException re) {
            throw exceptionOf(re);
        }
    }

    public static void crypto_core_salsa20(byte[] out, byte[] in, byte[] k) throws CryptoException {
        checkedArrayCopy(
                crypto_core_salsa20(in, k), 0,
                out, 0, crypto_core_salsa_OUTPUTBYTES);
    }

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