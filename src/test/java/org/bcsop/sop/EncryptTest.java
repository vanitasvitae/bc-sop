package org.bcsop.sop;

import org.junit.jupiter.api.Test;
import sop.ByteArrayAndResult;
import sop.DecryptionResult;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class EncryptTest {

    @Test
    public void test() throws IOException {
        BcSOP sop = new BcSOP();
        byte[] key = sop.generateKey()
                .userId("Alice <alice@example.org>")
                .generate()
                .getBytes();

        byte[] cert = sop.extractCert()
                .key(key)
                .getBytes();

        byte[] data = "Hello, World!\n".getBytes(StandardCharsets.UTF_8);

        byte[] encrypted = sop.encrypt()
                .withCert(cert)
                .signWith(key)
                .plaintext(data)
                .getBytes();

        ByteArrayAndResult<DecryptionResult> result = sop.decrypt()
                .verifyWithCert(cert)
                .withKey(key)
                .ciphertext(encrypted)
                .toByteArrayAndResult();
        byte[] decrypted = result.getBytes();

        assertEquals(1, result.getResult().getVerifications().size());

        assertArrayEquals(data, decrypted);
    }

    @Test
    public void roundTrip() throws IOException {
        String CERT = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
                "Comment: EB85 BB5F A33A 75E1 5E94  4E63 F231 550C 4F47 E38E\n" +
                "Comment: Alice Lovelace <alice@openpgp.example>\n" +
                "\n" +
                "xjMEXEcE6RYJKwYBBAHaRw8BAQdArjWwk3FAqyiFbFBKT4TzXcVBqPTB3gmzlC/U\n" +
                "b7O1u13NJkFsaWNlIExvdmVsYWNlIDxhbGljZUBvcGVucGdwLmV4YW1wbGU+wpAE\n" +
                "ExYIADgCGwMFCwkIBwIGFQoJCAsCBBYCAwECHgECF4AWIQTrhbtfozp14V6UTmPy\n" +
                "MVUMT0fjjgUCXaWfOgAKCRDyMVUMT0fjjukrAPoDnHBSogOmsHOsd9qGsiZpgRnO\n" +
                "dypvbm+QtXZqth9rvwD9HcDC0tC+PHAsO7OTh1S1TC9RiJsvawAfCPaQZoed8gLO\n" +
                "OARcRwTpEgorBgEEAZdVAQUBAQdAQv8GIa2rSTzgqbXCpDDYMiKRVitCsy203x3s\n" +
                "E9+eviIDAQgHwngEGBYIACAWIQTrhbtfozp14V6UTmPyMVUMT0fjjgUCXEcE6QIb\n" +
                "DAAKCRDyMVUMT0fjjlnQAQDFHUs6TIcxrNTtEZFjUFm1M0PJ1Dng/cDW4xN80fsn\n" +
                "0QEA22Kr7VkCjeAEC08VSTeV+QFsmz55/lntWkwYWhmvOgE=\n" +
                "=QX3Q\n" +
                "-----END PGP PUBLIC KEY BLOCK-----\n";
        String KEY = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
                "Comment: EB85 BB5F A33A 75E1 5E94  4E63 F231 550C 4F47 E38E\n" +
                "Comment: Alice Lovelace <alice@openpgp.example>\n" +
                "\n" +
                "xVgEXEcE6RYJKwYBBAHaRw8BAQdArjWwk3FAqyiFbFBKT4TzXcVBqPTB3gmzlC/U\n" +
                "b7O1u10AAP9XBeW6lzGOLx7zHH9AsUDUTb2pggYGMzd0P3ulJ2AfvQ4RzSZBbGlj\n" +
                "ZSBMb3ZlbGFjZSA8YWxpY2VAb3BlbnBncC5leGFtcGxlPsKQBBMWCAA4AhsDBQsJ\n" +
                "CAcCBhUKCQgLAgQWAgMBAh4BAheAFiEE64W7X6M6deFelE5j8jFVDE9H444FAl2l\n" +
                "nzoACgkQ8jFVDE9H447pKwD6A5xwUqIDprBzrHfahrImaYEZzncqb25vkLV2arYf\n" +
                "a78A/R3AwtLQvjxwLDuzk4dUtUwvUYibL2sAHwj2kGaHnfICx10EXEcE6RIKKwYB\n" +
                "BAGXVQEFAQEHQEL/BiGtq0k84Km1wqQw2DIikVYrQrMttN8d7BPfnr4iAwEIBwAA\n" +
                "/3/xFPG6U17rhTuq+07gmEvaFYKfxRB6sgAYiW6TMTpQEK7CeAQYFggAIBYhBOuF\n" +
                "u1+jOnXhXpROY/IxVQxPR+OOBQJcRwTpAhsMAAoJEPIxVQxPR+OOWdABAMUdSzpM\n" +
                "hzGs1O0RkWNQWbUzQ8nUOeD9wNbjE3zR+yfRAQDbYqvtWQKN4AQLTxVJN5X5AWyb\n" +
                "Pnn+We1aTBhaGa86AQ==\n" +
                "=3GfK\n" +
                "-----END PGP PRIVATE KEY BLOCK-----\n";

        BcSOP sop = new BcSOP();
        byte[] message = "Hello, World!\n".getBytes(StandardCharsets.UTF_8);
        byte[] ciphertext = sop.encrypt()
                .withCert(CERT.getBytes(StandardCharsets.UTF_8))
                .plaintext(message)
                .getBytes();
        byte[] plain = sop.decrypt()
                .withKey(KEY.getBytes(StandardCharsets.UTF_8))
                .ciphertext(ciphertext)
                .toByteArrayAndResult()
                .getBytes();

        assertArrayEquals(message, plain);
    }
}
