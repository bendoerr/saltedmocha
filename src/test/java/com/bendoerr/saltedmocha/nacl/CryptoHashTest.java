package com.bendoerr.saltedmocha.nacl;

import org.junit.Test;

import static org.bouncycastle.util.encoders.Hex.decode;
import static org.bouncycastle.util.encoders.Hex.toHexString;
import static org.junit.Assert.assertArrayEquals;

public class CryptoHashTest {
    @Test
    public void test_hash1() throws Exception {
        System.out.println("nacl-20110221/tests/hash.c");

        String ms = "testing\n";
        byte[] m = ms.getBytes();

        String outs = "24f950aac7b9ea9b3cb728228a0c82b67c39e96b4b344798870d5daee93e3ae5931baae8c7cacfea4b629452c38026a81d138bc7aad1af3ef7bfd5ec646d6c28";
        byte[] out = decode(outs);

        System.out.println("\tm: " + toHexString(m));

        byte[] h = CryptoHash.crypto_hash(m);

        System.out.println("\th: " + toHexString(h));
        assertArrayEquals(out, h);
    }
}
