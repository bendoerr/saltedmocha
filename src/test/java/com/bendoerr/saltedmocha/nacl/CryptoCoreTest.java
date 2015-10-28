package com.bendoerr.saltedmocha.nacl;

import org.bouncycastle.util.encoders.Hex;
import org.junit.Test;

import static com.bendoerr.saltedmocha.nacl.CryptoCore.crypto_core_hsalsa20;
import static com.bendoerr.saltedmocha.nacl.CryptoCore.crypto_core_salsa20;
import static com.bendoerr.saltedmocha.nacl.CryptoHash.crypto_hash_sha256;
import static java.lang.System.arraycopy;
import static org.bouncycastle.util.Arrays.copyOf;
import static org.bouncycastle.util.encoders.Hex.toHexString;
import static org.junit.Assert.assertArrayEquals;

public class CryptoCoreTest {
    @Test
    public void test_core1() throws Exception {
        System.out.println("nacl-20110221/tests/core1.c");

        byte[] shared = new byte[]{
                (byte) 0x4a, (byte) 0x5d, (byte) 0x9d, (byte) 0x5b, (byte) 0xa4, (byte) 0xce, (byte) 0x2d, (byte) 0xe1
                , (byte) 0x72, (byte) 0x8e, (byte) 0x3b, (byte) 0xf4, (byte) 0x80, (byte) 0x35, (byte) 0x0f, (byte) 0x25
                , (byte) 0xe0, (byte) 0x7e, (byte) 0x21, (byte) 0xc9, (byte) 0x47, (byte) 0xd1, (byte) 0x9e, (byte) 0x33
                , (byte) 0x76, (byte) 0xf0, (byte) 0x9b, (byte) 0x3c, (byte) 0x1e, (byte) 0x16, (byte) 0x17, (byte) 0x42
        };

        byte[] zero = new byte[32];

        byte[] out = new byte[]{
                (byte) 0x1b, (byte) 0x27, (byte) 0x55, (byte) 0x64, (byte) 0x73, (byte) 0xe9, (byte) 0x85, (byte) 0xd4
                , (byte) 0x62, (byte) 0xcd, (byte) 0x51, (byte) 0x19, (byte) 0x7a, (byte) 0x9a, (byte) 0x46, (byte) 0xc7
                , (byte) 0x60, (byte) 0x09, (byte) 0x54, (byte) 0x9e, (byte) 0xac, (byte) 0x64, (byte) 0x74, (byte) 0xf2
                , (byte) 0x06, (byte) 0xc4, (byte) 0xee, (byte) 0x08, (byte) 0x44, (byte) 0xf6, (byte) 0x83, (byte) 0x89
        };

        System.out.println("\tk: " + toHexString(shared));
        System.out.println("\tn: " + toHexString(zero));

        byte[] firstKey = crypto_core_hsalsa20(zero, shared);

        System.out.println("\th: " + toHexString(firstKey));

        assertArrayEquals(out, firstKey);
    }

    @Test
    public void test_core2() throws Exception {
        System.out.println("nacl-20110221/tests/core2.c");

        byte[] firstKey = new byte[]{
                (byte) 0x1b, (byte) 0x27, (byte) 0x55, (byte) 0x64, (byte) 0x73, (byte) 0xe9, (byte) 0x85, (byte) 0xd4
                , (byte) 0x62, (byte) 0xcd, (byte) 0x51, (byte) 0x19, (byte) 0x7a, (byte) 0x9a, (byte) 0x46, (byte) 0xc7
                , (byte) 0x60, (byte) 0x09, (byte) 0x54, (byte) 0x9e, (byte) 0xac, (byte) 0x64, (byte) 0x74, (byte) 0xf2
                , (byte) 0x06, (byte) 0xc4, (byte) 0xee, (byte) 0x08, (byte) 0x44, (byte) 0xf6, (byte) 0x83, (byte) 0x89
        };

        byte[] nonceprefex = new byte[]{
                (byte) 0x69, (byte) 0x69, (byte) 0x6e, (byte) 0xe9, (byte) 0x55, (byte) 0xb6, (byte) 0x2b, (byte) 0x73
                , (byte) 0xcd, (byte) 0x62, (byte) 0xbd, (byte) 0xa8, (byte) 0x75, (byte) 0xfc, (byte) 0x73, (byte) 0xd6
        };

        byte[] out = new byte[]{
                (byte) 0xdc, (byte) 0x90, (byte) 0x8d, (byte) 0xda, (byte) 0x0b, (byte) 0x93, (byte) 0x44, (byte) 0xa9
                , (byte) 0x53, (byte) 0x62, (byte) 0x9b, (byte) 0x73, (byte) 0x38, (byte) 0x20, (byte) 0x77, (byte) 0x88
                , (byte) 0x80, (byte) 0xf3, (byte) 0xce, (byte) 0xb4, (byte) 0x21, (byte) 0xbb, (byte) 0x61, (byte) 0xb9
                , (byte) 0x1c, (byte) 0xbd, (byte) 0x4c, (byte) 0x3e, (byte) 0x66, (byte) 0x25, (byte) 0x6c, (byte) 0xe4
        };

        System.out.println("\tk: " + toHexString(firstKey));
        System.out.println("\tn: " + toHexString(nonceprefex));

        byte[] secondKey = crypto_core_hsalsa20(nonceprefex, firstKey);

        System.out.println("\th: " + toHexString(secondKey));

        assertArrayEquals(out, secondKey);
    }

    @Test
    public void test_core3() throws Exception {
        System.out.println("nacl-20110221/tests/core3.c");

        byte[] secondKey = new byte[]{
                (byte) 0xdc, (byte) 0x90, (byte) 0x8d, (byte) 0xda, (byte) 0x0b, (byte) 0x93, (byte) 0x44, (byte) 0xa9
                , (byte) 0x53, (byte) 0x62, (byte) 0x9b, (byte) 0x73, (byte) 0x38, (byte) 0x20, (byte) 0x77, (byte) 0x88
                , (byte) 0x80, (byte) 0xf3, (byte) 0xce, (byte) 0xb4, (byte) 0x21, (byte) 0xbb, (byte) 0x61, (byte) 0xb9
                , (byte) 0x1c, (byte) 0xbd, (byte) 0x4c, (byte) 0x3e, (byte) 0x66, (byte) 0x25, (byte) 0x6c, (byte) 0xe4
        };

        byte[] noncesuffix = new byte[]{
                (byte) 0x82, (byte) 0x19, (byte) 0xe0, (byte) 0x03, (byte) 0x6b, (byte) 0x7a, (byte) 0x0b, (byte) 0x37
        };

        byte[] out = Hex.decode("662b9d0e3463029156069b12f918691a98f7dfb2ca0393c96bbfc6b1fbd630a2");

        System.out.println("\tk: " + toHexString(secondKey));
        System.out.println("\tn: " + toHexString(noncesuffix));

        byte[] output = new byte[64 * 256 * 256];
        byte[] in = copyOf(noncesuffix, 16);

        int pos = 0;
        do {
            do {
                byte[] c = crypto_core_salsa20(in, secondKey);
                arraycopy(c, 0, output, pos, 64);
                pos += 64;
            } while (++in[8] != 0);
        } while (++in[9] != 0);

        byte[] h = crypto_hash_sha256(output);

        System.out.println("\th: " + toHexString(h));

        assertArrayEquals(out, h);
    }

    @Test
    public void test_core4() throws Exception {
        System.out.println("nacl-20110221/tests/core4.c");

        byte[] k = new byte[]{
                (byte) 1, (byte)  2, (byte)  3, (byte)  4, (byte)  5, (byte)  6, (byte)  7, (byte)  8
                , (byte)  9, (byte)  10, (byte)  11, (byte)  12, (byte)  13, (byte)  14, (byte)  15, (byte)  16
                , (byte)  201, (byte)  202, (byte)  203, (byte)  204, (byte)  205, (byte)  206, (byte)  207, (byte)  208
                , (byte)  209, (byte)  210, (byte)  211, (byte)  212, (byte)  213, (byte)  214, (byte)  215, (byte)  216
        };

        byte[] in = new byte[] {
                (byte) 101, (byte) 102, (byte) 103, (byte) 104, (byte) 105, (byte) 106, (byte) 107, (byte) 108
                , (byte) 109, (byte) 110, (byte) 111, (byte) 112, (byte) 113, (byte) 114, (byte) 115, (byte) 116
        };

        byte[] out = new byte[] {
                (byte) 69, (byte)  37, (byte)  68, (byte)  39, (byte)  41, (byte)  15, (byte) 107, (byte) 193
                , (byte) 255, (byte) 139, (byte) 122, (byte)   6, (byte) 170, (byte) 233, (byte) 217, (byte)  98
                , (byte)  89, (byte) 144, (byte) 182, (byte) 106, (byte)  21, (byte)  51, (byte) 200, (byte)  65
                , (byte) 239, (byte)  49, (byte) 222, (byte)  34, (byte) 215, (byte) 114, (byte)  40, (byte) 126
                , (byte) 104, (byte) 197, (byte)   7, (byte) 225, (byte) 197, (byte) 153, (byte)  31, (byte)   2
                , (byte) 102, (byte)  78, (byte)  76, (byte) 176, (byte)  84, (byte) 245, (byte) 246, (byte) 184
                , (byte) 177, (byte) 160, (byte) 133, (byte) 130, (byte)   6, (byte)  72, (byte) 149, (byte) 119
                , (byte) 192, (byte) 195, (byte) 132, (byte) 236, (byte) 234, (byte) 103, (byte) 246, (byte)  74
        };

        System.out.println("\tk: " + toHexString(k));
        System.out.println("\tn: " + toHexString(in));

        byte[] h = crypto_core_salsa20(in, k);

        System.out.println("\th: " + toHexString(h));

        assertArrayEquals(out, h);
    }
}