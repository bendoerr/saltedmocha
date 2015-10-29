package com.bendoerr.saltedmocha.nacl;

import com.bendoerr.saltedmocha.CryptoException;

import java.math.BigInteger;

import static com.bendoerr.saltedmocha.Util.checkedArrayCopy;
import static com.bendoerr.saltedmocha.Util.validateLength;
import static com.bendoerr.saltedmocha.nacl.CryptoScalarMult.JavaCurve25519.curve25519;
import static java.math.BigInteger.ONE;
import static java.math.BigInteger.ZERO;
import static org.bouncycastle.util.Arrays.copyOf;
import static org.bouncycastle.util.Arrays.prepend;

public class CryptoScalarMult {

    public static final int crypto_scalarmult_curve25519_BYTES = 32;
    public static final int crypto_scalarmult_curve25519_SCALARBYTES = 32;

    public static final int crypto_scalarmult_BYTES = crypto_scalarmult_curve25519_BYTES;
    public static final int crypto_scalarmult_SCALARBYTES = crypto_scalarmult_curve25519_SCALARBYTES;

    public static final byte[] curve25519_BASE = prepend(
            new byte[crypto_scalarmult_curve25519_BYTES - 1], (byte) 0x09);

    /**
     * This function multiplies a group element p by an integer n. It returns
     * the resulting group element q of length crypto_scalarmult_BYTES. The
     * function raises an exception if p.size() is not crypto_scalarmult_BYTES.
     * It also raises an exception if n.size() is not
     * crypto_scalarmult_SCALARBYTES.
     */
    public static void crypto_scalarmult(byte[] q_out, byte[] n, byte[] p) throws CryptoException {
        crypto_scalarmult_curve25519(q_out, n, p);
    }

    public static byte[] crypto_scalarmult(byte[] n, byte[] p) throws CryptoException {
        return crypto_scalarmult_curve25519(n, p);
    }

    /**
     * The crypto_scalarmult_base function computes the scalar product of a
     * standard group element and an integer n. It returns the resulting group
     * element q of length crypto_scalarmult_BYTES. It raises an exception if
     * n.size() is not crypto_scalarmult_SCALARBYTES.
     */
    public static void crypto_scalarmult_base(byte[] q_out, byte[] n) throws CryptoException {
        crypto_scalarmult_curve25519_base(q_out, n);
    }

    public static byte[] crypto_scalarmult_base(byte[] n) throws CryptoException {
        return crypto_scalarmult_curve25519_base(n);
    }

    public static void crypto_scalarmult_curve25519(byte[] q_out, byte[] n, byte[] p) throws CryptoException {
        validateLength(n, crypto_scalarmult_curve25519_SCALARBYTES,
                "integer n", "crypto_scalarmult_curve25519_SCALARBYTES");

        validateLength(p, crypto_scalarmult_curve25519_BYTES,
                "group element p", "crypto_scalarmult_curve25519_BYTES");

        byte[] s = curve25519(n, p);
        checkedArrayCopy(
                s, 0,
                q_out, 0, s.length);
    }

    public static byte[] crypto_scalarmult_curve25519(byte[] n, byte[] p) throws CryptoException {
        byte[] q = new byte[crypto_scalarmult_curve25519_BYTES];
        crypto_scalarmult_curve25519(q, n, p);
        return q;
    }

    public static void crypto_scalarmult_curve25519_base(byte[] q_out, byte[] n) throws CryptoException {
        crypto_scalarmult_curve25519(q_out, n, curve25519_BASE);
    }

    public static byte[] crypto_scalarmult_curve25519_base(byte[] n) throws CryptoException {
        return crypto_scalarmult_curve25519(n, curve25519_BASE);
    }

    /**
     * Based on the Python Implementation included in http://cr.yp.to/highspeed/naclcrypto-20090310.pdf
     * Would love to use BouncyCastle primitives to replace this.
     * Note there is also org.whispersystems.curve25519.java.scalarmult.crypto_scalarmult but I wrote this to drop that dependency.
     * In addition, empirically, this is pretty slow.
     */
    public static class JavaCurve25519 {
        static BigInteger P = BigInteger.valueOf(2).pow(255).subtract(BigInteger.valueOf(19));
        static BigInteger A = BigInteger.valueOf(486662);
        static BigInteger TWO = BigInteger.valueOf(2);

        static BigInteger expmod(BigInteger b, BigInteger e, BigInteger m) {
            if (e.equals(ZERO))
                return ONE;

            BigInteger t = expmod(b, e.divide(TWO), m).pow(2).mod(m);
            if (!e.and(ONE).equals(ZERO)) {
                t = t.multiply(b).mod(m);
            }

            return t;
        }

        static BigInteger inv(BigInteger x) {
            return expmod(x, P.subtract(TWO), P);
        }

        static Pair add(Pair n, Pair m, Pair d) {
            BigInteger four = BigInteger.valueOf(4);
            BigInteger x = four.multiply((m.x.multiply(n.x).subtract(m.z.multiply(n.z))).pow(2)).multiply(d.z);
            BigInteger z = four.multiply((m.x.multiply(n.z).subtract(m.z.multiply(n.x))).pow(2)).multiply(d.x);
            return new Pair(x.mod(P), z.mod(P));
        }

        static Pair twice(Pair n) {
            BigInteger four = BigInteger.valueOf(4);

            BigInteger x = ((n.x.pow(2)).subtract(n.z.pow(2))).pow(2);
            BigInteger z = four.multiply(n.x).multiply(n.z).multiply((n.x.pow(2)).add(A.multiply(n.x).multiply(n.z)).add(n.z.pow(2)));

            return new Pair(x.mod(P), z.mod(P));
        }

        static Pair[] f(Pair one, Pair two, BigInteger m) {
            if (m.equals(ONE))
                return new Pair[]{one, two};

            Pair[] pma = f(one, two, m.divide(TWO));
            Pair pm = pma[0];
            Pair pm1 = pma[1];

            if (!m.and(ONE).equals(ZERO)) {
                return new Pair[]{
                        add(pm, pm1, one), twice(pm1)};
            }

            return new Pair[]{
                    twice(pm), add(pm, pm1, one)};
        }

        public static BigInteger curve25519(BigInteger n, BigInteger base) {
            Pair one = new Pair(base, ONE);
            Pair two = twice(one);
            Pair[] a = f(one, two, n);
            Pair xz = a[0];
            return (xz.x.multiply(inv(xz.z))).mod(P);
        }

        public static byte[] curve25519(byte[] n, byte[] base) {
            return unpack(
                    curve25519(
                            pack(clampc(n)), pack(base)));
        }

        public static byte[] clampc(final byte[] n) {
            byte[] c = copyOf(n, n.length);
            c[0] &= 248;
            c[31] &= 127;
            c[31] |= 64;
            return c;
        }

        public static BigInteger pack(byte[] n) {
            return new BigInteger(reverse(n));
        }

        static byte[] reverse(byte[] n) {
            // flip between little edan and big
            // Java BigIntegers are big
            byte[] s = new byte[n.length];
            for (int i = 0; i < n.length; i++)
                s[i] = n[n.length - 1 - i];
            return s;
        }

        public static byte[] unpack(BigInteger n) {
            return reverse(n.toByteArray());
        }

        private static class Pair {
            public BigInteger x;
            public BigInteger z;

            public Pair(BigInteger x, BigInteger z) {
                this.x = x;
                this.z = z;
            }
        }
    }
}
