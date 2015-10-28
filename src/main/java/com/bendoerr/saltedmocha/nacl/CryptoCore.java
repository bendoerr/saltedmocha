package com.bendoerr.saltedmocha.nacl;

public class CryptoCore {

    public static int crypto_core_hsalsa_INPUTBYTES = 16;
    public static int crypto_core_hsalsa_OUTPUTBYTES = 32;
    public static int crypto_core_hsalsa_KEYBYTES = 32;

    public static int crypto_core_salsa_INPUTBYTES = 16;
    public static int crypto_core_salsa_OUTPUTBYTES = 64;
    public static int crypto_core_salsa_KEYBYTES = 32;

    public static byte[] crypto_core_hsalsa20(byte[] in, byte[] k) {
        return new CryptoStream.Salsa20Cipher(in, k, true).core();
    }

    public static byte[] crypto_core_salsa20(byte[] in, byte[] k) {
        return new CryptoStream.Salsa20Cipher(in, k).core();
    }
}
