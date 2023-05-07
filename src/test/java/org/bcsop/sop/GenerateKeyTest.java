package org.bcsop.sop;

import org.junit.jupiter.api.Test;

import java.io.IOException;

public class GenerateKeyTest {

    @Test
    public void generateKeyTest() throws IOException {
        new BcGenerateKey().userId("Alice <alice@example.org>")
                .withKeyPassword("sw0rdf1sh")
                .generate()
                .writeTo(System.out);
    }
}
