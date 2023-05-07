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
}
