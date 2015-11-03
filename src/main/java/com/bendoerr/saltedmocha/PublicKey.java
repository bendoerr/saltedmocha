package com.bendoerr.saltedmocha;

import javax.security.auth.DestroyFailedException;
import javax.security.auth.Destroyable;

import static com.bendoerr.saltedmocha.Util.java_memzero;

public class PublicKey implements Destroyable {

    private boolean destroyed = false;

    private final byte[] key;

    public PublicKey(byte[] key) {
        // TODO Check key size
        this.key = key;
    }

    public byte[] getKey() {
        return key;
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
