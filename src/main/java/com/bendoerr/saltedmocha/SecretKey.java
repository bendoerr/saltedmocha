package com.bendoerr.saltedmocha;

import com.bendoerr.saltedmocha.nacl.CryptoScalarMult;

import javax.security.auth.DestroyFailedException;
import javax.security.auth.Destroyable;
import java.security.SecureRandom;

import static com.bendoerr.saltedmocha.Util.java_memzero;
import static com.bendoerr.saltedmocha.Util.nanoTimeNonce;
import static com.bendoerr.saltedmocha.nacl.CryptoAuth.crypto_auth;
import static com.bendoerr.saltedmocha.nacl.CryptoAuth.crypto_auth_verify;
import static com.bendoerr.saltedmocha.nacl.CryptoBox.*;
import static com.bendoerr.saltedmocha.nacl.CryptoSecretBox.*;

public class SecretKey implements Destroyable {

    private boolean destroyed = false;

    private final byte[] key;

    public SecretKey(byte[] key) {
        // TODO Check key size
        this.key = key;
    }

    public SecretKey() {
        this.key = new byte[crypto_box_SECRETKEYBYTES];
        new SecureRandom().nextBytes(this.key);
    }

    public byte[] getKey() {
        return key;
    }

    public PublicKey generatePublicKey() throws CryptoException {
        return new PublicKey(CryptoScalarMult.crypto_scalarmult_base(key));
    }

    public EncryptedMessage encrypt(Text m) throws CryptoException {
        byte[] n = nanoTimeNonce(crypto_secretbox_NONCEBYTES);
        byte[] c = crypto_secretbox(m.getByteArray(), n, key);
        return new EncryptedMessage(c, n);
    }

    public EncryptedMessage encrypt(Text m, PublicKey receiver) throws CryptoException {
        byte[] n = nanoTimeNonce(crypto_box_NONCEBYTES);
        byte[] c = crypto_box(m.getByteArray(), n, receiver.getKey(), key);
        return new EncryptedMessage(c, n);
    }

    public Text decrypt(EncryptedMessage m) throws CryptoException {
        return Text.fromBytes(
                crypto_secretbox_open(
                        m.getCipherText().getByteArray(),
                        m.getNonce().getByteArray(),
                        key));
    }

    public Text decrypt(EncryptedMessage m, PublicKey sender) throws CryptoException {
        return Text.fromBytes(
                crypto_box_open(
                        m.getCipherText().getByteArray(),
                        m.getNonce().getByteArray(),
                        sender.getKey(),
                        key));
    }

    public Text authenticate(Text m) throws CryptoException {
        return Text.fromBytes(
                crypto_auth(m.getByteArray(), key));
    }

    public void verify(Text m, Text authTag) throws CryptoException {
        crypto_auth_verify(authTag.getByteArray(), m.getByteArray(), key);
    }

    @Override
    public void destroy() throws DestroyFailedException {
        java_memzero(key);
        destroyed = true;
    }

    @Override
    public boolean isDestroyed() {
        return destroyed;
    }
}
