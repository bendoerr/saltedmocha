package com.bendoerr.saltedmocha.nacl;

import com.bendoerr.saltedmocha.CryptoException;

import java.security.SecureRandom;

import static com.bendoerr.saltedmocha.Util.validateLength;
import static com.bendoerr.saltedmocha.nacl.CryptoCore.crypto_core_hsalsa20;
import static com.bendoerr.saltedmocha.nacl.CryptoCore.crypto_core_hsalsa_INPUTBYTES;
import static com.bendoerr.saltedmocha.nacl.CryptoScalarMult.crypto_scalarmult_base;
import static com.bendoerr.saltedmocha.nacl.CryptoScalarMult.crypto_scalarmult_curve25519;
import static com.bendoerr.saltedmocha.nacl.CryptoSecretBox.crypto_secretbox_xsalsa20poly1305;
import static com.bendoerr.saltedmocha.nacl.CryptoSecretBox.crypto_secretbox_xsalsa20poly1305_open;

public class CryptoBox {

    public static final int crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES = 32;
    public static final int crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES = 32;
    public static final int crypto_box_curve25519xsalsa20poly1305_NONCEBYTES = 24;
    public static final int crypto_box_curve25519xsalsa20poly1305_BEFORENM = 32;

    public static final int crypto_box_SECRETKEYBYTES = crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES;
    public static final int crypto_box_PUBLICKEYBYTES = crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES;
    public static final int crypto_box_NONCEBYTES = crypto_box_curve25519xsalsa20poly1305_NONCEBYTES;
    public static final int crypto_box_BEFORENM = crypto_box_curve25519xsalsa20poly1305_BEFORENM;

    /**
     * The crypto_box function encrypts and authenticates a message m using the
     * sender's secret key sk, the receiver's public key pk, and a nonce n. The
     * crypto_box function returns the resulting ciphertext c. The function
     * raises an exception if sk.size() is not crypto_box_SECRETKEYBYTES or if
     * pk.size() is not crypto_box_PUBLICKEYBYTES or if n.size() is not
     * crypto_box_NONCEBYTES.
     */
    public static void crypto_box(byte[] c_out, byte[] m, byte[] n, byte[] pk, byte[] sk) throws CryptoException {
        crypto_box_curve25519xsalsa20poly1305(c_out, m, n, pk, sk);
    }

    public static byte[] crypto_box(byte[] m, byte[] n, byte[] pk, byte[] sk) throws CryptoException {
        return crypto_box_curve25519xsalsa20poly1305(m, n, pk, sk);
    }

    /**
     * The crypto_box_open function verifies and decrypts a ciphertext c using
     * the receiver's secret key sk, the sender's public key pk, and a nonce n.
     * The crypto_box_open function returns the resulting plaintext m.
     * <p>
     * If the ciphertext fails verification, crypto_box_open raises an
     * exception. The function also raises an exception if sk.size() is not
     * crypto_box_SECRETKEYBYTES or if pk.size() is not
     * crypto_box_PUBLICKEYBYTES or if n.size() is not crypto_box_NONCEBYTES.
     */
    public static void crypto_box_open(byte[] m_out, byte[] c, byte[] n, byte[] pk, byte[] sk) throws CryptoException {
        crypto_box_curve25519xsalsa20poly1305_open(m_out, c, n, pk, sk);
    }

    public static void crypto_box_beforenm(byte[] k_out, byte[] pk, byte[] sk) throws CryptoException {
        crypto_box_curve25519xsalsa20poly1305_beforenm(k_out, pk, sk);
    }

    public static void crypto_box_afternm(byte[] c_out, byte[] m, byte[] n, byte[] k) throws CryptoException {
        crypto_box_curve25519xsalsa20poly1305_afternm(c_out, m, n, k);
    }

    public static void crypto_box_open_afternm(byte[] m_out, byte[] c, byte[] n, byte[] k) throws CryptoException {
        crypto_box_curve25519xsalsa20poly1305_open_afternm(m_out, c, n, k);
    }

    public static byte[] crypto_box_open(byte[] c, byte[] n, byte[] pk, byte[] sk) throws CryptoException {
        return crypto_box_curve25519xsalsa20poly1305_open(c, n, pk, sk);
    }

    public static byte[] crypto_box_beforenm(byte[] pk, byte[] sk) throws CryptoException {
        return crypto_box_curve25519xsalsa20poly1305_beforenm(pk, sk);
    }

    public static byte[] crypto_box_afternm(byte[] m, byte[] n, byte[] k) throws CryptoException {
        return crypto_box_curve25519xsalsa20poly1305_afternm(m, n, k);
    }

    public static byte[] crypto_box_open_afternm(byte[] c, byte[] n, byte[] k) throws CryptoException {
        return crypto_box_curve25519xsalsa20poly1305_open_afternm(c, n, k);
    }

    public static void crypto_box_curve25519xsalsa20poly1305(
            byte[] c_out, byte[] m, byte[] n, byte[] pk, byte[] sk) throws CryptoException {
        validateLength(pk, crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES,
                "public key", "crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES");

        validateLength(sk, crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES,
                "secret key", "crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES");

        validateLength(n, crypto_box_curve25519xsalsa20poly1305_NONCEBYTES,
                "nonce", "crypto_box_curve25519xsalsa20poly1305_NONCEBYTES");

        crypto_box_curve25519xsalsa20poly1305_afternm(
                c_out, m, n, crypto_box_curve25519xsalsa20poly1305_beforenm(pk, sk));
    }

    public static byte[] crypto_box_curve25519xsalsa20poly1305(
            byte[] m, byte[] n, byte[] pk, byte[] sk) throws CryptoException {
        validateLength(pk, crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES,
                "public key", "crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES");

        validateLength(sk, crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES,
                "secret key", "crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES");

        validateLength(n, crypto_box_curve25519xsalsa20poly1305_NONCEBYTES,
                "nonce", "crypto_box_curve25519xsalsa20poly1305_NONCEBYTES");

        return crypto_box_curve25519xsalsa20poly1305_afternm(
                m, n, crypto_box_curve25519xsalsa20poly1305_beforenm(pk, sk));
    }

    public static void crypto_box_curve25519xsalsa20poly1305_open(byte[] m_out, byte[] c, byte[] n, byte[] pk, byte[] sk) throws CryptoException {
        validateLength(pk, crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES,
                "public key", "crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES");

        validateLength(sk, crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES,
                "secret key", "crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES");

        validateLength(n, crypto_box_curve25519xsalsa20poly1305_NONCEBYTES,
                "nonce", "crypto_box_curve25519xsalsa20poly1305_NONCEBYTES");

        crypto_box_curve25519xsalsa20poly1305_open_afternm(m_out, c, n,
                crypto_box_curve25519xsalsa20poly1305_beforenm(pk, sk));
    }

    public static byte[] crypto_box_curve25519xsalsa20poly1305_open(byte[] c, byte[] n, byte[] pk, byte[] sk) throws CryptoException {
        validateLength(pk, crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES,
                "public key", "crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES");

        validateLength(sk, crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES,
                "secret key", "crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES");

        validateLength(n, crypto_box_curve25519xsalsa20poly1305_NONCEBYTES,
                "nonce", "crypto_box_curve25519xsalsa20poly1305_NONCEBYTES");

        return crypto_box_curve25519xsalsa20poly1305_open_afternm(c, n,
                crypto_box_curve25519xsalsa20poly1305_beforenm(pk, sk));
    }

    public static void crypto_box_curve25519xsalsa20poly1305_beforenm(byte[] k_out, byte[] pk, byte[] sk) throws CryptoException {
        crypto_core_hsalsa20(k_out,
                new byte[crypto_core_hsalsa_INPUTBYTES],
                crypto_scalarmult_curve25519(sk, pk));
    }

    public static byte[] crypto_box_curve25519xsalsa20poly1305_beforenm(byte[] pk, byte[] sk) throws CryptoException {
        return crypto_core_hsalsa20(
                new byte[crypto_core_hsalsa_INPUTBYTES],
                crypto_scalarmult_curve25519(sk, pk));
    }

    public static void crypto_box_curve25519xsalsa20poly1305_afternm(byte[] c_out, byte[] m, byte[] n, byte[] k) throws CryptoException {
        crypto_secretbox_xsalsa20poly1305(c_out, m, n, k);
    }

    public static byte[] crypto_box_curve25519xsalsa20poly1305_afternm(byte[] m, byte[] n, byte[] k) throws CryptoException {
        return crypto_secretbox_xsalsa20poly1305(m, n, k);
    }

    public static void crypto_box_curve25519xsalsa20poly1305_open_afternm(byte[] m_out, byte[] c, byte[] n, byte[] k) throws CryptoException {
        crypto_secretbox_xsalsa20poly1305_open(m_out, c, n, k);
    }

    public static byte[] crypto_box_curve25519xsalsa20poly1305_open_afternm(byte[] c, byte[] n, byte[] k) throws CryptoException {
        return crypto_secretbox_xsalsa20poly1305_open(c, n, k);
    }

    /**
     * The crypto_box_keypair function randomly generates a secret key and a
     * corresponding public key. It puts the secret key into sk and returns the
     * public key. It requires that sk has crypto_box_SECRETKEYBYTES bytes and
     * that pk has crypto_box_PUBLICKEYBYTES bytes.
     */
    public static void crypto_box_keypair(byte[] out_pk, byte[] out_sk) throws CryptoException {
        crypto_box_curve25519xsalsa20poly1305_keypair(out_pk, out_sk);
    }

    public static byte[] crypto_box_keypair(byte[] outsk) throws CryptoException {
        return crypto_box_curve25519xsalsa20poly1305_keypair(outsk);
    }

    public static byte[] crypto_box_curve25519xsalsa20poly1305_keypair(byte[] out_sk) throws CryptoException {
        validateLength(out_sk, crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES,
                "secret key", "crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES");

        new SecureRandom().nextBytes(out_sk);
        return crypto_scalarmult_base(out_sk);
    }

    public static void crypto_box_curve25519xsalsa20poly1305_keypair(byte[] out_pk, byte[] out_sk) throws CryptoException {
        validateLength(out_sk, crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES,
                "secret key", "crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES");

        validateLength(out_pk, crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES,
                "public key", "crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES");

        new SecureRandom().nextBytes(out_sk);
        crypto_scalarmult_base(out_pk, out_sk);
    }
}
