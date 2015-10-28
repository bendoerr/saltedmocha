package com.bendoerr.saltedmocha.nacl;

import org.bouncycastle.util.Arrays;
import org.junit.Test;

import java.security.SecureRandom;
import java.util.Random;

import static com.bendoerr.saltedmocha.nacl.CryptoAuth.*;
import static org.bouncycastle.util.encoders.Hex.toHexString;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.fail;

public class CryptoAuthTest {
    @Test
    public void test_auth() throws Exception {
        byte[] key = new byte[] { 'J', 'e', 'f', 'e' };
        key = Arrays.concatenate(key, new byte[32 - key.length]);

        byte[] c = new byte[] {
                'w', 'h', 'a', 't', ' ', 'd', 'o', ' ', 'y', 'a', ' ', 'w', 'a', 'n', 't', ' ', 'f', 'o', 'r', ' ', 'n', 'o', 't', 'h', 'i', 'n', 'g', '?'
        };

        byte[] out = new byte[] {
                (byte) 0x16,(byte) 0x4b,(byte) 0x7a,(byte) 0x7b,(byte) 0xfc,(byte) 0xf8,(byte) 0x19,(byte) 0xe2
                ,(byte) 0xe3,(byte) 0x95,(byte) 0xfb,(byte) 0xe7,(byte) 0x3b,(byte) 0x56,(byte) 0xe0,(byte) 0xa3
                ,(byte) 0x87,(byte) 0xbd,(byte) 0x64,(byte) 0x22,(byte) 0x2e,(byte) 0x83,(byte) 0x1f,(byte) 0xd6
                ,(byte) 0x10,(byte) 0x27,(byte) 0x0c,(byte) 0xd7,(byte) 0xea,(byte) 0x25,(byte) 0x05,(byte) 0x54
        };

        System.out.println("\tk: " + toHexString(key));
        System.out.println("\tc: " + toHexString(c));

        byte[] a = crypto_auth_hmacsha512256(c, key);

        System.out.println("\ta: " + toHexString(a));

        assertArrayEquals(out, a);
    }

    @Test
    public void test_auth4() throws Exception {
        System.out.println("nacl-20110221/tests/auth4.cpp");

        byte[] key = new byte[] {
                (byte) 0x01,(byte) 0x02,(byte) 0x03,(byte) 0x04,(byte) 0x05,(byte) 0x06,(byte) 0x07,(byte) 0x08
                ,(byte) 0x09,(byte) 0x0a,(byte) 0x0b,(byte) 0x0c,(byte) 0x0d,(byte) 0x0e,(byte) 0x0f,(byte) 0x10
                ,(byte) 0x11,(byte) 0x12,(byte) 0x13,(byte) 0x14,(byte) 0x15,(byte) 0x16,(byte) 0x17,(byte) 0x18
                ,(byte) 0x19,(byte) 0x1a,(byte) 0x1b,(byte) 0x1c,(byte) 0x1d,(byte) 0x1e,(byte) 0x1f,(byte) 0x20
        };

        byte[] c = new byte[] {
                (byte) 0xcd,(byte) 0xcd,(byte) 0xcd,(byte) 0xcd,(byte) 0xcd,(byte) 0xcd,(byte) 0xcd,(byte) 0xcd
                ,(byte) 0xcd,(byte) 0xcd,(byte) 0xcd,(byte) 0xcd,(byte) 0xcd,(byte) 0xcd,(byte) 0xcd,(byte) 0xcd
                ,(byte) 0xcd,(byte) 0xcd,(byte) 0xcd,(byte) 0xcd,(byte) 0xcd,(byte) 0xcd,(byte) 0xcd,(byte) 0xcd
                ,(byte) 0xcd,(byte) 0xcd,(byte) 0xcd,(byte) 0xcd,(byte) 0xcd,(byte) 0xcd,(byte) 0xcd,(byte) 0xcd
                ,(byte) 0xcd,(byte) 0xcd,(byte) 0xcd,(byte) 0xcd,(byte) 0xcd,(byte) 0xcd,(byte) 0xcd,(byte) 0xcd
                ,(byte) 0xcd,(byte) 0xcd,(byte) 0xcd,(byte) 0xcd,(byte) 0xcd,(byte) 0xcd,(byte) 0xcd,(byte) 0xcd
                ,(byte) 0xcd,(byte) 0xcd
        };

        byte[] a = new byte[] {
                (byte) 0x37,(byte) 0x2e,(byte) 0xfc,(byte) 0xf9,(byte) 0xb4,(byte) 0x0b,(byte) 0x35,(byte) 0xc2
                ,(byte) 0x11,(byte) 0x5b,(byte) 0x13,(byte) 0x46,(byte) 0x90,(byte) 0x3d,(byte) 0x2e,(byte) 0xf4
                ,(byte) 0x2f,(byte) 0xce,(byte) 0xd4,(byte) 0x6f,(byte) 0x08,(byte) 0x46,(byte) 0xe7,(byte) 0x25
                ,(byte) 0x7b,(byte) 0xb1,(byte) 0x56,(byte) 0xd3,(byte) 0xd7,(byte) 0xb3,(byte) 0x0d,(byte) 0x3f
        };

        System.out.println("\tk: " + toHexString(key));
        System.out.println("\tc: " + toHexString(c));
        System.out.println("\ta: " + toHexString(a));

        crypto_auth_hmacsha256_verify(a, c, key);
    }

    @Test
    public void test_auth6() throws Exception {
        System.out.println("nacl-20110221/tests/auth6.cpp");
        Random r = new SecureRandom();
        int work = 10000;

        for (int len = 0; len < work; len++) {
            byte[] key = new byte[crypto_auth_hmacsha512256_KEYBYTES];
            byte[] c = new byte[len];

            r.nextBytes(key);
            r.nextBytes(c);

            byte[] a = crypto_auth_hmacsha512256(c, key);
            crypto_auth_hmacsha512256_verify(a, c, key);

            if (c.length > 0) {
                c[r.nextInt(len)] += 1 + r.nextInt(254);
                try {
                    crypto_auth_hmacsha512256_verify(a, c, key);
                    fail("forgery allowed at " + len);
                } catch (CryptoAuth.CryptoAuthException e) {}

                a[r.nextInt(a.length)] += 1 + r.nextInt(254);
                try {
                    crypto_auth_hmacsha512256_verify(a, c, key);
                    fail("forgery allowed at " + len);
                } catch (CryptoAuth.CryptoAuthException e) {}
            }
        }

        System.out.println("\tno forgery allowed in " + work + " random attempts");
    }
}
