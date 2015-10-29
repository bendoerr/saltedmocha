package com.bendoerr.saltedmocha.nacl;

import com.bendoerr.saltedmocha.CryptoException;
import org.bouncycastle.crypto.engines.Salsa20Engine;
import org.bouncycastle.crypto.engines.XSalsa20Engine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Pack;

import static com.bendoerr.saltedmocha.CryptoException.exceptionOf;
import static com.bendoerr.saltedmocha.Util.checkedArrayCopy;
import static com.bendoerr.saltedmocha.Util.validateLength;

public class CryptoStream {

    public static int crypto_stream_xsalsa_KEYBYTES = 32;
    public static int crypto_stream_xsalsa_NONCEBYTES = 24;

    public static int crypto_stream_KEYBYTES = crypto_stream_xsalsa_KEYBYTES;
    public static int crypto_stream_NONCEBYTES = crypto_stream_xsalsa_NONCEBYTES;

    public static int crypto_stream_salsa_KEYBYTES = 32;
    public static int crypto_stream_salsa_NONCEBYTES = 8;

    /**
     * The crypto_stream function produces a clen-byte stream c as a function
     * of a secret key k and a nonce n. The function raises an exception if
     * k.size() is not crypto_stream_KEYBYTES. It also raises an exception
     * if n.size() is not crypto_stream_NONCEBYTES.
     */
    public static byte[] crypto_stream(int len, byte[] n, byte[] k) throws CryptoException {
        return crypto_stream_xsalsa20(len, n, k);
    }

    public static byte[] crypto_stream_xor(byte[] m, byte[] n, byte[] k) throws CryptoException {
        return crypto_stream_xsalsa20_xor(m, n, k);
    }

    public static byte[] crypto_stream_salsa20(int len, byte[] n, byte[] k) throws CryptoException {
        validateLength(k, crypto_stream_salsa_KEYBYTES,
                "key", "crypto_stream_salsa_KEYBYTES");

        validateLength(n, crypto_stream_salsa_NONCEBYTES,
                "nonce", "crypto_stream_salsa_NONCEBYTES");

        try {
            return new Salsa20Cipher(n, k).stream(len);
        } catch (RuntimeException re) {
            throw exceptionOf(re);
        }
    }

    public static byte[] crypto_stream_salsa20_xor(byte[] m, byte[] n, byte[] k) throws CryptoException {
        validateLength(k, crypto_stream_salsa_KEYBYTES,
                "key", "crypto_stream_salsa_KEYBYTES");

        validateLength(n, crypto_stream_salsa_NONCEBYTES,
                "nonce", "crypto_stream_salsa_NONCEBYTES");

        try {
            return new Salsa20Cipher(n, k).xor(m);
        } catch (RuntimeException re) {
            throw exceptionOf(re);
        }
    }

    public static void crypto_stream_xsalsa20(byte[] out, byte[] n, byte[] k) throws CryptoException {
        checkedArrayCopy(
                crypto_stream_xsalsa20(out.length, n, k), 0,
                out, 0, out.length);
    }

    public static byte[] crypto_stream_xsalsa20(int len, byte[] n, byte[] k) throws CryptoException {
        validateLength(k, crypto_stream_xsalsa_KEYBYTES,
                "key", "crypto_stream_xsalsa_KEYBYTES");

        validateLength(n, crypto_stream_xsalsa_NONCEBYTES,
                "nonce", "crypto_stream_xsalsa_NONCEBYTES");

        try {
            return new XSalsa20Cipher(n, k).stream(len);
        } catch (RuntimeException re) {
            throw exceptionOf(re);
        }
    }

    public static void crypto_stream_xsalsa20_xor(byte[] c_out, byte[] m, byte[] n, byte[] k) throws CryptoException {
        checkedArrayCopy(
                crypto_stream_xsalsa20_xor(m, n, k), 0,
                c_out, 0, c_out.length);
    }

    public static byte[] crypto_stream_xsalsa20_xor(byte[] m, byte[] n, byte[] k) throws CryptoException {
        validateLength(k, crypto_stream_xsalsa_KEYBYTES,
                "key", "crypto_stream_xsalsa_KEYBYTES");

        validateLength(n, crypto_stream_xsalsa_NONCEBYTES,
                "nonce", "crypto_stream_xsalsa_NONCEBYTES");

//        return crypto_stream_salsa20_xor(m,
//                copyOfRange(n, 16, 24),
//                crypto_core_hsalsa20(copyOfRange(n, 0, 16), k));
        try {
            return new XSalsa20Cipher(n, k).xor(m);
        } catch (RuntimeException re) {
            throw exceptionOf(re);
        }
    }

    /**
     * Helper around BouncyCastle's Salsa20 to expose the parts we need.
     */
    public static class Salsa20Cipher extends Salsa20Engine {

        private final boolean hsalsa;

        public Salsa20Cipher(byte[] n, byte[] k) {
            this(n, k, false);
        }

        public Salsa20Cipher(byte[] n, byte[] k, boolean hsalsa) {
            this.hsalsa = hsalsa;
            if (hsalsa || n.length == 16)
                setKey(k, n);
            else
                init(false, new ParametersWithIV(new KeyParameter(k), n));
        }

        public byte[] core() {
            int[] f = new int[16];
            Salsa20Engine.salsaCore(20, engineState, f);

            if (hsalsa) {
                // HSalsa doesn't add x + z
                for (int i = 0; i < engineState.length; i++)
                    f[i] = f[i] - engineState[i];
            }

            if (hsalsa) {
                // HSalsa20 specifies these bytes to be used.
                return Pack.intToLittleEndian(new int[]{f[0], f[5], f[10], f[15], f[6], f[7], f[8], f[9]});
            } else {
                return Pack.intToLittleEndian(f);
            }
        }

        public byte[] stream(int len) {
            byte[] in = new byte[len];
            byte[] out = new byte[len];
            processBytes(in, 0, len, out, 0);
            return out;
        }

        public byte[] xor(byte[] m) {
            byte[] c = new byte[m.length];
            processBytes(m, 0, m.length, c, 0);
            return c;
        }

        protected void setKey(byte[] keyBytes, byte[] ivBytes) {
            super.setKey(keyBytes, ivBytes);
            if (ivBytes.length == 16) {
                engineState[8] = Pack.littleEndianToInt(ivBytes, 8);
                engineState[9] = Pack.littleEndianToInt(ivBytes, 12);
            }
        }
    }

    /**
     * Helper around BouncyCastle's XSalsa20 to expose the parts we need.
     */
    public static class XSalsa20Cipher extends XSalsa20Engine {

        public XSalsa20Cipher(byte[] n, byte[] k) {
            init(false, new ParametersWithIV(new KeyParameter(k), n));
        }

        public byte[] stream(int len) {
            byte[] in = new byte[len];
            byte[] out = new byte[len];
            processBytes(in, 0, len, out, 0);
            return out;
        }

        public byte[] xor(byte[] m) {
            byte[] c = new byte[m.length];
            processBytes(m, 0, m.length, c, 0);
            return c;
        }

        public byte[] core() {
            int[] f = new int[16];
            Salsa20Engine.salsaCore(20, engineState, f);
            return Pack.intToLittleEndian(f);
        }
    }

}
