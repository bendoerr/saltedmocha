package com.bendoerr.saltedmocha;

import javax.security.auth.DestroyFailedException;
import javax.security.auth.Destroyable;

public class EncryptedMessage implements Destroyable {

    private Text cipherText;

    private Text nonce;

    public EncryptedMessage(Text cipherText, Text nonce) {
        this.cipherText = cipherText;
        this.nonce = nonce;
    }

    public EncryptedMessage(byte[] cipherText, byte[] nonce) {
        this.cipherText = Text.fromBytes(cipherText);
        this.nonce = Text.fromBytes(nonce);
    }

    public EncryptedMessage(String cipherHexString, String nonceHexString) {
        this.cipherText = Text.fromHexString(cipherHexString);
        this.cipherText = Text.fromHexString(nonceHexString);
    }

    public Text getCipherText() {
        return cipherText;
    }

    public Text getNonce() {
        return nonce;
    }

    @Override
    public void destroy() throws DestroyFailedException {
        cipherText.destroy();
        nonce.destroy();
    }

    @Override
    public boolean isDestroyed() {
        return cipherText.isDestroyed() || nonce.isDestroyed();
    }
}
