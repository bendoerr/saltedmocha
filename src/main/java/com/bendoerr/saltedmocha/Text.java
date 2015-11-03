package com.bendoerr.saltedmocha;

import org.bouncycastle.util.encoders.Hex;

import javax.security.auth.DestroyFailedException;
import javax.security.auth.Destroyable;

public interface Text extends Destroyable {

    static Text fromBytes(byte[] text) {
        return new ByteArrayBackedHexEncodedStringText(text);
    }

    static Text fromHexString(String hexText) {
        return new ByteArrayBackedHexEncodedStringText(hexText);
    }

    byte[] getByteArray();

    String getString();

    class ByteArrayBackedHexEncodedStringText implements Text {

        private boolean destroyed;

        private final byte[] text;

        public ByteArrayBackedHexEncodedStringText(byte[] text) {
            this.text = text;
        }

        public ByteArrayBackedHexEncodedStringText(String text) {
            this.text = Hex.decode(text);
        }

        @Override
        public byte[] getByteArray() {
            if (isDestroyed())
                return null;

            return text;
        }

        @Override
        public String getString() {
            if (isDestroyed())
                return null;

            return Hex.toHexString(text);
        }

        @Override
        public void destroy() throws DestroyFailedException {
            Util.java_memzero(text);
            destroyed = true;
        }

        @Override
        public boolean isDestroyed() {
            return destroyed;
        }
    }
}
