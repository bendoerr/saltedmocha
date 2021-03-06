package com.bendoerr.saltedmocha.nacl;

import com.bendoerr.saltedmocha.CryptoException;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;

import static com.bendoerr.saltedmocha.CryptoException.exceptionOf;

/**
 * <p>CryptoHash class.</p>
 */
public class CryptoHash {

    /**
     * Constant <code>crypto_hash_sha256_BYTES=32</code>
     */
    public static final int crypto_hash_sha256_BYTES = 32;
    /**
     * Constant <code>crypto_hash_sha512_BYTES=64</code>
     */
    public static final int crypto_hash_sha512_BYTES = 64;
    /**
     * Constant <code>crypto_hash_BYTES=crypto_hash_sha512_BYTES</code>
     */
    public static final int crypto_hash_BYTES = crypto_hash_sha512_BYTES;
    private CryptoHash() {
    }

    /**
     * The crypto_hash function hashes a message m. It returns a hash h. The
     * output length h.size() is always crypto_hash_BYTES.
     *
     * @param h_out an array of byte.
     * @param m     an array of byte.
     * @throws com.bendoerr.saltedmocha.CryptoException if any.
     */
    public static void crypto_hash(byte[] h_out, byte[] m) throws CryptoException {
        crypto_hash_sha512(h_out, m);
    }

    /**
     * <p>crypto_hash.</p>
     *
     * @param m an array of byte.
     * @return an array of byte.
     * @throws com.bendoerr.saltedmocha.CryptoException if any.
     */
    public static byte[] crypto_hash(byte[] m) throws CryptoException {
        return crypto_hash_sha512(m);
    }

    /**
     * <p>crypto_hash_sha256.</p>
     *
     * @param h_out an array of byte.
     * @param m     an array of byte.
     * @throws com.bendoerr.saltedmocha.CryptoException if any.
     */
    public static void crypto_hash_sha256(byte[] h_out, byte[] m) throws CryptoException {
        try {
            hash(h_out, m, new SHA256Digest());
        } catch (RuntimeException re) {
            throw exceptionOf(re);
        }
    }

    /**
     * <p>crypto_hash_sha256.</p>
     *
     * @param m an array of byte.
     * @return an array of byte.
     * @throws com.bendoerr.saltedmocha.CryptoException if any.
     */
    public static byte[] crypto_hash_sha256(byte[] m) throws CryptoException {
        byte[] h_out = new byte[crypto_hash_sha256_BYTES];
        crypto_hash_sha256(h_out, m);
        return h_out;
    }

    /**
     * <p>crypto_hash_sha512.</p>
     *
     * @param h_out an array of byte.
     * @param m     an array of byte.
     * @throws com.bendoerr.saltedmocha.CryptoException if any.
     */
    public static void crypto_hash_sha512(byte[] h_out, byte[] m) throws CryptoException {
        try {
            hash(h_out, m, new SHA512Digest());
        } catch (RuntimeException re) {
            throw exceptionOf(re);
        }
    }

    /**
     * <p>crypto_hash_sha512.</p>
     *
     * @param m an array of byte.
     * @return an array of byte.
     * @throws com.bendoerr.saltedmocha.CryptoException if any.
     */
    public static byte[] crypto_hash_sha512(byte[] m) throws CryptoException {
        byte[] h_out = new byte[crypto_hash_sha512_BYTES];
        crypto_hash_sha512(h_out, m);
        return h_out;
    }

    private static void hash(byte[] h_out, byte[] m, Digest md) {
        md.update(m, 0, m.length);
        md.doFinal(h_out, 0);
    }
}
