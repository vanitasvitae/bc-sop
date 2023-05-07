package org.bcsop.sop;

import org.junit.jupiter.api.Test;
import sop.enums.InlineSignAs;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

public class InlineSignTest {

    @Test
    public void test() throws IOException {
        BcSOP sop = new BcSOP();

        byte[] key = sop.generateKey()
                .userId("Alice <alice@example.org>")
                .generate()
                .getBytes();

        byte[] data = "Hello, World!\n".getBytes(StandardCharsets.UTF_8);

        sop.inlineSign()
                .key(key)
                .data(data)
                .writeTo(System.out);
    }

    @Test
    public void cleartextSignTest() throws IOException {
        BcSOP sop = new BcSOP();

        byte[] key = sop.generateKey()
                .userId("Alice <alice@example.org>")
                .generate()
                .getBytes();

        byte[] data = "Hello, World!\n".getBytes(StandardCharsets.UTF_8);

        sop.inlineSign()
                .mode(InlineSignAs.clearsigned)
                .key(key)
                .data(data)
                .writeTo(System.out);
    }
}
