package com.bendoerr.saltedmocha.libsodium;

import com.bendoerr.saltedmocha.CryptoException;
import com.bendoerr.saltedmocha.Util;
import org.junit.Test;

import java.security.SecureRandom;
import java.util.Random;

import static com.bendoerr.saltedmocha.libsodium.CryptoBoxEasy.*;
//import static com.bendoerr.saltedmocha.nacl.CryptoBox.*;
import static com.bendoerr.saltedmocha.nacl.CryptoBox.crypto_box_beforenm;
import static com.bendoerr.saltedmocha.nacl.CryptoBox.crypto_box_keypair;
import static java.lang.System.arraycopy;
import static org.bouncycastle.util.Arrays.*;
import static org.bouncycastle.util.encoders.Hex.toHexString;
import static org.junit.Assert.*;

public class CryptoBoxEasyTest {
    @Test
    public void test_box_easy_a() throws Exception {
        System.out.println("libsodium/test/default/box_easy.c");

        byte[] alicesk = new byte[]{
                (byte) 0x77, (byte) 0x07, (byte) 0x6d, (byte) 0x0a, (byte) 0x73,
                (byte) 0x18, (byte) 0xa5, (byte) 0x7d, (byte) 0x3c, (byte) 0x16,
                (byte) 0xc1, (byte) 0x72, (byte) 0x51, (byte) 0xb2, (byte) 0x66,
                (byte) 0x45, (byte) 0xdf, (byte) 0x4c, (byte) 0x2f, (byte) 0x87,
                (byte) 0xeb, (byte) 0xc0, (byte) 0x99, (byte) 0x2a, (byte) 0xb1,
                (byte) 0x77, (byte) 0xfb, (byte) 0xa5, (byte) 0x1d, (byte) 0xb9,
                (byte) 0x2c, (byte) 0x2a};

        byte[] bobpk = new byte[]{
                (byte) 0xde, (byte) 0x9e, (byte) 0xdb, (byte) 0x7d, (byte) 0x7b,
                (byte) 0x7d, (byte) 0xc1, (byte) 0xb4, (byte) 0xd3, (byte) 0x5b,
                (byte) 0x61, (byte) 0xc2, (byte) 0xec, (byte) 0xe4, (byte) 0x35,
                (byte) 0x37, (byte) 0x3f, (byte) 0x83, (byte) 0x43, (byte) 0xc8,
                (byte) 0x5b, (byte) 0x78, (byte) 0x67, (byte) 0x4d, (byte) 0xad,
                (byte) 0xfc, (byte) 0x7e, (byte) 0x14, (byte) 0x6f, (byte) 0x88,
                (byte) 0x2b, (byte) 0x4f};

        byte[] nonce = new byte[]{
                (byte) 0x69, (byte) 0x69, (byte) 0x6e, (byte) 0xe9, (byte) 0x55,
                (byte) 0xb6, (byte) 0x2b, (byte) 0x73, (byte) 0xcd, (byte) 0x62,
                (byte) 0xbd, (byte) 0xa8, (byte) 0x75, (byte) 0xfc, (byte) 0x73,
                (byte) 0xd6, (byte) 0x82, (byte) 0x19, (byte) 0xe0, (byte) 0x03,
                (byte) 0x6b, (byte) 0x7a, (byte) 0x0b, (byte) 0x37};

        byte[] m = new byte[]{
                (byte) 0xbe, (byte) 0x07, (byte) 0x5f, (byte) 0xc5, (byte) 0x3c,
                (byte) 0x81, (byte) 0xf2, (byte) 0xd5, (byte) 0xcf, (byte) 0x14,
                (byte) 0x13, (byte) 0x16, (byte) 0xeb, (byte) 0xeb, (byte) 0x0c,
                (byte) 0x7b, (byte) 0x52, (byte) 0x28, (byte) 0xc5, (byte) 0x2a,
                (byte) 0x4c, (byte) 0x62, (byte) 0xcb, (byte) 0xd4, (byte) 0x4b,
                (byte) 0x66, (byte) 0x84, (byte) 0x9b, (byte) 0x64, (byte) 0x24,
                (byte) 0x4f, (byte) 0xfc, (byte) 0xe5, (byte) 0xec, (byte) 0xba,
                (byte) 0xaf, (byte) 0x33, (byte) 0xbd, (byte) 0x75, (byte) 0x1a,
                (byte) 0x1a, (byte) 0xc7, (byte) 0x28, (byte) 0xd4, (byte) 0x5e,
                (byte) 0x6c, (byte) 0x61, (byte) 0x29, (byte) 0x6c, (byte) 0xdc,
                (byte) 0x3c, (byte) 0x01, (byte) 0x23, (byte) 0x35, (byte) 0x61,
                (byte) 0xf4, (byte) 0x1d, (byte) 0xb6, (byte) 0x6c, (byte) 0xce,
                (byte) 0x31, (byte) 0x4a, (byte) 0xdb, (byte) 0x31, (byte) 0x0e,
                (byte) 0x3b, (byte) 0xe8, (byte) 0x25, (byte) 0x0c, (byte) 0x46,
                (byte) 0xf0, (byte) 0x6d, (byte) 0xce, (byte) 0xea, (byte) 0x3a,
                (byte) 0x7f, (byte) 0xa1, (byte) 0x34, (byte) 0x80, (byte) 0x57,
                (byte) 0xe2, (byte) 0xf6, (byte) 0x55, (byte) 0x6a, (byte) 0xd6,
                (byte) 0xb1, (byte) 0x31, (byte) 0x8a, (byte) 0x02, (byte) 0x4a,
                (byte) 0x83, (byte) 0x8f, (byte) 0x21, (byte) 0xaf, (byte) 0x1f,
                (byte) 0xde, (byte) 0x04, (byte) 0x89, (byte) 0x77, (byte) 0xeb,
                (byte) 0x48, (byte) 0xf5, (byte) 0x9f, (byte) 0xfd, (byte) 0x49,
                (byte) 0x24, (byte) 0xca, (byte) 0x1c, (byte) 0x60, (byte) 0x90,
                (byte) 0x2e, (byte) 0x52, (byte) 0xf0, (byte) 0xa0, (byte) 0x89,
                (byte) 0xbc, (byte) 0x76, (byte) 0x89, (byte) 0x70, (byte) 0x40,
                (byte) 0xe0, (byte) 0x82, (byte) 0xf9, (byte) 0x37, (byte) 0x76,
                (byte) 0x38, (byte) 0x48, (byte) 0x64, (byte) 0x5e, (byte) 0x07,
                (byte) 0x05};

        byte[] out = new byte[]{
                (byte) 0xf3, (byte) 0xff, (byte) 0xc7, (byte) 0x70, (byte) 0x3f,
                (byte) 0x94, (byte) 0x00, (byte) 0xe5, (byte) 0x2a, (byte) 0x7d,
                (byte) 0xfb, (byte) 0x4b, (byte) 0x3d, (byte) 0x33, (byte) 0x05,
                (byte) 0xd9, (byte) 0x8e, (byte) 0x99, (byte) 0x3b, (byte) 0x9f,
                (byte) 0x48, (byte) 0x68, (byte) 0x12, (byte) 0x73, (byte) 0xc2,
                (byte) 0x96, (byte) 0x50, (byte) 0xba, (byte) 0x32, (byte) 0xfc,
                (byte) 0x76, (byte) 0xce, (byte) 0x48, (byte) 0x33, (byte) 0x2e,
                (byte) 0xa7, (byte) 0x16, (byte) 0x4d, (byte) 0x96, (byte) 0xa4,
                (byte) 0x47, (byte) 0x6f, (byte) 0xb8, (byte) 0xc5, (byte) 0x31,
                (byte) 0xa1, (byte) 0x18, (byte) 0x6a, (byte) 0xc0, (byte) 0xdf,
                (byte) 0xc1, (byte) 0x7c, (byte) 0x98, (byte) 0xdc, (byte) 0xe8,
                (byte) 0x7b, (byte) 0x4d, (byte) 0xa7, (byte) 0xf0, (byte) 0x11,
                (byte) 0xec, (byte) 0x48, (byte) 0xc9, (byte) 0x72, (byte) 0x71,
                (byte) 0xd2, (byte) 0xc2, (byte) 0x0f, (byte) 0x9b, (byte) 0x92,
                (byte) 0x8f, (byte) 0xe2, (byte) 0x27, (byte) 0x0d, (byte) 0x6f,
                (byte) 0xb8, (byte) 0x63, (byte) 0xd5, (byte) 0x17, (byte) 0x38,
                (byte) 0xb4, (byte) 0x8e, (byte) 0xee, (byte) 0xe3, (byte) 0x14,
                (byte) 0xa7, (byte) 0xcc, (byte) 0x8a, (byte) 0xb9, (byte) 0x32,
                (byte) 0x16, (byte) 0x45, (byte) 0x48, (byte) 0xe5, (byte) 0x26,
                (byte) 0xae, (byte) 0x90, (byte) 0x22, (byte) 0x43, (byte) 0x68,
                (byte) 0x51, (byte) 0x7a, (byte) 0xcf, (byte) 0xea, (byte) 0xbd,
                (byte) 0x6b, (byte) 0xb3, (byte) 0x73, (byte) 0x2b, (byte) 0xc0,
                (byte) 0xe9, (byte) 0xda, (byte) 0x99, (byte) 0x83, (byte) 0x2b,
                (byte) 0x61, (byte) 0xca, (byte) 0x01, (byte) 0xb6, (byte) 0xde,
                (byte) 0x56, (byte) 0x24, (byte) 0x4a, (byte) 0x9e, (byte) 0x88,
                (byte) 0xd5, (byte) 0xf9, (byte) 0xb3, (byte) 0x79, (byte) 0x73,
                (byte) 0xf6, (byte) 0x22, (byte) 0xa4, (byte) 0x3d, (byte) 0x14,
                (byte) 0xa6, (byte) 0x59, (byte) 0x9b, (byte) 0x1f, (byte) 0x65,
                (byte) 0x4c, (byte) 0xb4, (byte) 0x5a, (byte) 0x74, (byte) 0xe3,
                (byte) 0x55, (byte) 0xa5};

        System.out.println("\t m: " + toHexString(m));
        System.out.println("\t n: " + toHexString(nonce));
        System.out.println("\tpk: " + toHexString(bobpk));
        System.out.println("\tsk: " + toHexString(alicesk));

        byte[] c = new byte[m.length + crypto_box_MACBYTES];
        crypto_box_easy(c, m, nonce, bobpk, alicesk);

        System.out.println("\t c: " + toHexString(c));

        assertArrayEquals(out, c);
    }

    @Test
    public void test_box_easy_b() throws Exception {
        System.out.println("libsodium/test/default/box_easy.c");

        byte[] alicesk = new byte[]{
                (byte) 0x77, (byte) 0x07, (byte) 0x6d, (byte) 0x0a, (byte) 0x73,
                (byte) 0x18, (byte) 0xa5, (byte) 0x7d, (byte) 0x3c, (byte) 0x16,
                (byte) 0xc1, (byte) 0x72, (byte) 0x51, (byte) 0xb2, (byte) 0x66,
                (byte) 0x45, (byte) 0xdf, (byte) 0x4c, (byte) 0x2f, (byte) 0x87,
                (byte) 0xeb, (byte) 0xc0, (byte) 0x99, (byte) 0x2a, (byte) 0xb1,
                (byte) 0x77, (byte) 0xfb, (byte) 0xa5, (byte) 0x1d, (byte) 0xb9,
                (byte) 0x2c, (byte) 0x2a};

        byte[] bobpk = new byte[]{
                (byte) 0xde, (byte) 0x9e, (byte) 0xdb, (byte) 0x7d, (byte) 0x7b,
                (byte) 0x7d, (byte) 0xc1, (byte) 0xb4, (byte) 0xd3, (byte) 0x5b,
                (byte) 0x61, (byte) 0xc2, (byte) 0xec, (byte) 0xe4, (byte) 0x35,
                (byte) 0x37, (byte) 0x3f, (byte) 0x83, (byte) 0x43, (byte) 0xc8,
                (byte) 0x5b, (byte) 0x78, (byte) 0x67, (byte) 0x4d, (byte) 0xad,
                (byte) 0xfc, (byte) 0x7e, (byte) 0x14, (byte) 0x6f, (byte) 0x88,
                (byte) 0x2b, (byte) 0x4f};

        byte[] nonce = new byte[]{
                (byte) 0x69, (byte) 0x69, (byte) 0x6e, (byte) 0xe9, (byte) 0x55,
                (byte) 0xb6, (byte) 0x2b, (byte) 0x73, (byte) 0xcd, (byte) 0x62,
                (byte) 0xbd, (byte) 0xa8, (byte) 0x75, (byte) 0xfc, (byte) 0x73,
                (byte) 0xd6, (byte) 0x82, (byte) 0x19, (byte) 0xe0, (byte) 0x03,
                (byte) 0x6b, (byte) 0x7a, (byte) 0x0b, (byte) 0x37};

        byte[] m = new byte[]{
                (byte) 0xbe, (byte) 0x07, (byte) 0x5f, (byte) 0xc5, (byte) 0x3c,
                (byte) 0x81, (byte) 0xf2, (byte) 0xd5, (byte) 0xcf, (byte) 0x14,
                (byte) 0x13, (byte) 0x16, (byte) 0xeb, (byte) 0xeb, (byte) 0x0c,
                (byte) 0x7b, (byte) 0x52, (byte) 0x28, (byte) 0xc5, (byte) 0x2a,
                (byte) 0x4c, (byte) 0x62, (byte) 0xcb, (byte) 0xd4, (byte) 0x4b,
                (byte) 0x66, (byte) 0x84, (byte) 0x9b, (byte) 0x64, (byte) 0x24,
                (byte) 0x4f, (byte) 0xfc, (byte) 0xe5, (byte) 0xec, (byte) 0xba,
                (byte) 0xaf, (byte) 0x33, (byte) 0xbd, (byte) 0x75, (byte) 0x1a,
                (byte) 0x1a, (byte) 0xc7, (byte) 0x28, (byte) 0xd4, (byte) 0x5e,
                (byte) 0x6c, (byte) 0x61, (byte) 0x29, (byte) 0x6c, (byte) 0xdc,
                (byte) 0x3c, (byte) 0x01, (byte) 0x23, (byte) 0x35, (byte) 0x61,
                (byte) 0xf4, (byte) 0x1d, (byte) 0xb6, (byte) 0x6c, (byte) 0xce,
                (byte) 0x31, (byte) 0x4a, (byte) 0xdb, (byte) 0x31, (byte) 0x0e,
                (byte) 0x3b, (byte) 0xe8, (byte) 0x25, (byte) 0x0c, (byte) 0x46,
                (byte) 0xf0, (byte) 0x6d, (byte) 0xce, (byte) 0xea, (byte) 0x3a,
                (byte) 0x7f, (byte) 0xa1, (byte) 0x34, (byte) 0x80, (byte) 0x57,
                (byte) 0xe2, (byte) 0xf6, (byte) 0x55, (byte) 0x6a, (byte) 0xd6,
                (byte) 0xb1, (byte) 0x31, (byte) 0x8a, (byte) 0x02, (byte) 0x4a,
                (byte) 0x83, (byte) 0x8f, (byte) 0x21, (byte) 0xaf, (byte) 0x1f,
                (byte) 0xde, (byte) 0x04, (byte) 0x89, (byte) 0x77, (byte) 0xeb,
                (byte) 0x48, (byte) 0xf5, (byte) 0x9f, (byte) 0xfd, (byte) 0x49,
                (byte) 0x24, (byte) 0xca, (byte) 0x1c, (byte) 0x60, (byte) 0x90,
                (byte) 0x2e, (byte) 0x52, (byte) 0xf0, (byte) 0xa0, (byte) 0x89,
                (byte) 0xbc, (byte) 0x76, (byte) 0x89, (byte) 0x70, (byte) 0x40,
                (byte) 0xe0, (byte) 0x82, (byte) 0xf9, (byte) 0x37, (byte) 0x76,
                (byte) 0x38, (byte) 0x48, (byte) 0x64, (byte) 0x5e, (byte) 0x07,
                (byte) 0x05};

        byte[] out = new byte[]{
                (byte) 0xf3, (byte) 0xff, (byte) 0xc7, (byte) 0x70, (byte) 0x3f,
                (byte) 0x94, (byte) 0x00, (byte) 0xe5, (byte) 0x2a, (byte) 0x7d,
                (byte) 0xfb, (byte) 0x4b, (byte) 0x3d, (byte) 0x33, (byte) 0x05,
                (byte) 0xd9, (byte) 0x8e, (byte) 0x99, (byte) 0x3b, (byte) 0x9f,
                (byte) 0x48, (byte) 0x68, (byte) 0x12, (byte) 0x73, (byte) 0xc2,
                (byte) 0x96, (byte) 0x50, (byte) 0xba, (byte) 0x32, (byte) 0xfc,
                (byte) 0x76, (byte) 0xce, (byte) 0x48, (byte) 0x33, (byte) 0x2e,
                (byte) 0xa7, (byte) 0x16, (byte) 0x4d, (byte) 0x96, (byte) 0xa4,
                (byte) 0x47, (byte) 0x6f, (byte) 0xb8, (byte) 0xc5, (byte) 0x31,
                (byte) 0xa1, (byte) 0x18, (byte) 0x6a, (byte) 0xc0, (byte) 0xdf,
                (byte) 0xc1, (byte) 0x7c, (byte) 0x98, (byte) 0xdc, (byte) 0xe8,
                (byte) 0x7b, (byte) 0x4d, (byte) 0xa7, (byte) 0xf0, (byte) 0x11,
                (byte) 0xec, (byte) 0x48, (byte) 0xc9, (byte) 0x72, (byte) 0x71,
                (byte) 0xd2, (byte) 0xc2, (byte) 0x0f, (byte) 0x9b, (byte) 0x92,
                (byte) 0x8f, (byte) 0xe2, (byte) 0x27, (byte) 0x0d, (byte) 0x6f,
                (byte) 0xb8, (byte) 0x63, (byte) 0xd5, (byte) 0x17, (byte) 0x38,
                (byte) 0xb4, (byte) 0x8e, (byte) 0xee, (byte) 0xe3, (byte) 0x14,
                (byte) 0xa7, (byte) 0xcc, (byte) 0x8a, (byte) 0xb9, (byte) 0x32,
                (byte) 0x16, (byte) 0x45, (byte) 0x48, (byte) 0xe5, (byte) 0x26,
                (byte) 0xae, (byte) 0x90, (byte) 0x22, (byte) 0x43, (byte) 0x68,
                (byte) 0x51, (byte) 0x7a, (byte) 0xcf, (byte) 0xea, (byte) 0xbd,
                (byte) 0x6b, (byte) 0xb3, (byte) 0x73, (byte) 0x2b, (byte) 0xc0,
                (byte) 0xe9, (byte) 0xda, (byte) 0x99, (byte) 0x83, (byte) 0x2b,
                (byte) 0x61, (byte) 0xca, (byte) 0x01, (byte) 0xb6, (byte) 0xde,
                (byte) 0x56, (byte) 0x24, (byte) 0x4a, (byte) 0x9e, (byte) 0x88,
                (byte) 0xd5, (byte) 0xf9, (byte) 0xb3, (byte) 0x79, (byte) 0x73,
                (byte) 0xf6, (byte) 0x22, (byte) 0xa4, (byte) 0x3d, (byte) 0x14,
                (byte) 0xa6, (byte) 0x59, (byte) 0x9b, (byte) 0x1f, (byte) 0x65,
                (byte) 0x4c, (byte) 0xb4, (byte) 0x5a, (byte) 0x74, (byte) 0xe3,
                (byte) 0x55, (byte) 0xa5};

        byte[] c = new byte[m.length + crypto_box_MACBYTES];
        byte[] bigM = new byte[Util.MAX_ARRAY_SIZE];
        arraycopy(m, 0, bigM, 0, m.length);

        try {
            crypto_box_easy(c, bigM, nonce, bobpk, alicesk);
            fail("should have thrown exception");
        } catch (CryptoException exception) {
            assertEquals("m is too big", exception.getMessage());
        }
    }

    @Test
    public void test_box_easy2_a() throws Exception {
        System.out.println("libsodium/test/default/box_easy2.c");
        Random r = new SecureRandom();

        int mlen = r.nextInt(10000);
        byte[] m = new byte[mlen];
        byte[] m2 = new byte[mlen];
        byte[] c = new byte[mlen + crypto_box_MACBYTES];

        byte[] alicepk = new byte[crypto_box_PUBLICKEYBYTES];
        byte[] alicesk = new byte[crypto_box_SECRETKEYBYTES];
        byte[] bobpk = new byte[crypto_box_PUBLICKEYBYTES];
        byte[] bobsk = new byte[crypto_box_SECRETKEYBYTES];
        byte[] nonce = new byte[crypto_box_NONCEBYTES];

        crypto_box_keypair(alicepk, alicesk);
        crypto_box_keypair(bobpk, bobsk);
        r.nextBytes(m);
        r.nextBytes(nonce);

        // Basic Open Close
        crypto_box_easy(c, m, nonce, bobpk, alicesk);
        crypto_box_open_easy(m2, c, nonce, alicepk, bobsk);
        assertArrayEquals(m, m2);


        // What is this testing?
//        arraycopy(m, 0, c, 0, mlen);
//        crypto_box_easy(c, c, nonce, bobpk, alicesk);
    }

    @Test
    public void test_box_easy2_b() throws Exception {
        System.out.println("libsodium/test/default/box_easy2.c");
        Random r = new SecureRandom();

        int mlen = r.nextInt(10000);
        byte[] m = new byte[mlen];
        byte[] m2 = new byte[mlen];
        byte[] c = new byte[mlen + crypto_box_MACBYTES];

        byte[] alicepk = new byte[crypto_box_PUBLICKEYBYTES];
        byte[] alicesk = new byte[crypto_box_SECRETKEYBYTES];
        byte[] bobpk = new byte[crypto_box_PUBLICKEYBYTES];
        byte[] bobsk = new byte[crypto_box_SECRETKEYBYTES];
        byte[] nonce = new byte[crypto_box_NONCEBYTES];

        crypto_box_keypair(alicepk, alicesk);
        crypto_box_keypair(bobpk, bobsk);
        r.nextBytes(m);
        r.nextBytes(nonce);

        // Can't open truncated message
        for (int i = 0; i < mlen + crypto_box_MACBYTES; i++) {
            byte[] small = new byte[i];
            arraycopy(c, 0, small, 0, i);
            try {
                crypto_box_open_easy(m2, small, nonce, alicepk, bobsk);
                fail("short open() should have failed");
            } catch (CryptoException exception) {
                Throwable cause = exception.getCause() != null ? exception.getCause() : exception;

                if (i < crypto_box_MACBYTES)
                    assertEquals("mlen=" + mlen + " and i=" + i,
                            cause.getMessage(), "c is too small");
                else
                    assertEquals("mlen=" + mlen + " and i=" + i,
                            cause.getMessage(), "failed to verify");
            }
        }
    }

    @Test
    public void test_box_easy2_c() throws Exception {
        System.out.println("libsodium/test/default/box_easy2.c");
        Random r = new SecureRandom();

        int mlen = r.nextInt(10000);
        byte[] m = new byte[mlen];
        byte[] m2 = new byte[mlen];
        byte[] c = new byte[mlen + crypto_box_MACBYTES];

        byte[] alicepk = new byte[crypto_box_PUBLICKEYBYTES];
        byte[] alicesk = new byte[crypto_box_SECRETKEYBYTES];
        byte[] bobpk = new byte[crypto_box_PUBLICKEYBYTES];
        byte[] bobsk = new byte[crypto_box_SECRETKEYBYTES];
        byte[] nonce = new byte[crypto_box_NONCEBYTES];

        crypto_box_keypair(alicepk, alicesk);
        crypto_box_keypair(bobpk, bobsk);
        r.nextBytes(m);
        r.nextBytes(nonce);

        arraycopy(m, 0, c, 0, mlen);
        crypto_box_easy(c, copyOf(c, mlen), nonce, bobpk, alicesk);
        assertFalse(areEqual(copyOf(m, mlen), copyOf(c, mlen)));
        assertFalse(areEqual(copyOf(m, mlen), copyOfRange(c, crypto_box_MACBYTES, c.length)));
        crypto_box_open_easy(c, copyOf(c, mlen + crypto_box_MACBYTES), nonce, alicepk, bobsk);
    }

    @Test
    public void test_box_easy2_d() throws Exception {
        System.out.println("libsodium/test/default/box_easy2.c");
        Random r = new SecureRandom();

        int mlen = r.nextInt(10000);
        byte[] m = new byte[mlen];
        byte[] m2 = new byte[mlen];
        byte[] c = new byte[mlen + crypto_box_MACBYTES];

        byte[] alicepk = new byte[crypto_box_PUBLICKEYBYTES];
        byte[] alicesk = new byte[crypto_box_SECRETKEYBYTES];
        byte[] bobpk = new byte[crypto_box_PUBLICKEYBYTES];
        byte[] bobsk = new byte[crypto_box_SECRETKEYBYTES];
        byte[] nonce = new byte[crypto_box_NONCEBYTES];
        byte[] k1 = new byte[crypto_box_BEFORENMBYTES];
        byte[] k2 = new byte[crypto_box_BEFORENMBYTES];

        crypto_box_keypair(alicepk, alicesk);
        crypto_box_keypair(bobpk, bobsk);
        r.nextBytes(m);
        r.nextBytes(nonce);

        crypto_box_beforenm(k1, alicepk, bobsk);
        crypto_box_beforenm(k2, bobpk, alicesk);

        try {
            crypto_box_easy_afternm(c, copyOf(m, Util.MAX_ARRAY_SIZE), nonce, k1);
            fail("crypto_box_easy_afternm() with a short ciphertext should have failed");
        } catch (CryptoException ce) {
            assertEquals("m is too big", ce.getMessage());
        }

        crypto_box_easy_afternm(c, m, nonce, k1);
        crypto_box_open_easy_afternm(m2, c, nonce, k2);
        assertArrayEquals(m, m2);

        try {
            crypto_box_open_easy_afternm(m2, copyOf(c, crypto_box_MACBYTES - 1), nonce, k2);
        } catch (CryptoException exception) {
            Throwable cause = exception.getCause() != null ? exception.getCause() : exception;
            assertEquals("c is too small", cause.getMessage());
        }
    }

    @Test
    public void test_box_easy2_e() throws Exception {
        System.out.println("libsodium/test/default/box_easy2.c");
        Random r = new SecureRandom();

        int mlen = r.nextInt(10000);
        byte[] m = new byte[mlen];
        byte[] m2 = new byte[mlen];
        byte[] c = new byte[mlen];

        byte[] alicepk = new byte[crypto_box_PUBLICKEYBYTES];
        byte[] alicesk = new byte[crypto_box_SECRETKEYBYTES];
        byte[] bobpk = new byte[crypto_box_PUBLICKEYBYTES];
        byte[] bobsk = new byte[crypto_box_SECRETKEYBYTES];
        byte[] nonce = new byte[crypto_box_NONCEBYTES];
        byte[] mac = new byte[crypto_box_MACBYTES];

        crypto_box_keypair(alicepk, alicesk);
        crypto_box_keypair(bobpk, bobsk);
        r.nextBytes(m);
        r.nextBytes(nonce);

        crypto_box_detatched(c, mac, m, nonce, alicepk, bobsk);
        crypto_box_open_detached(m2, c, mac, nonce, bobpk, alicesk);

        assertArrayEquals(m, m2);
    }

    @Test
    public void test_box_easy2_f() throws Exception {
        System.out.println("libsodium/test/default/box_easy2.c");
        Random r = new SecureRandom();

        int mlen = r.nextInt(10000);
        byte[] m = new byte[mlen];
        byte[] m2 = new byte[mlen];
        byte[] c = new byte[mlen];

        byte[] alicepk = new byte[crypto_box_PUBLICKEYBYTES];
        byte[] alicesk = new byte[crypto_box_SECRETKEYBYTES];
        byte[] bobpk = new byte[crypto_box_PUBLICKEYBYTES];
        byte[] bobsk = new byte[crypto_box_SECRETKEYBYTES];
        byte[] nonce = new byte[crypto_box_NONCEBYTES];
        byte[] k1 = new byte[crypto_box_BEFORENMBYTES];
        byte[] k2 = new byte[crypto_box_BEFORENMBYTES];
        byte[] mac = new byte[crypto_box_MACBYTES];

        crypto_box_keypair(alicepk, alicesk);
        crypto_box_keypair(bobpk, bobsk);
        r.nextBytes(m);
        r.nextBytes(nonce);

        crypto_box_beforenm(k1, alicepk, bobsk);
        crypto_box_beforenm(k2, bobpk, alicesk);

        crypto_box_detached_afternm(c, mac, m, nonce, k1);
        crypto_box_open_detached_afternm(m2, c, mac, nonce, k2);

        assertArrayEquals(m, m2);
    }
}
