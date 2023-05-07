package org.bcsop.sop;

import org.junit.jupiter.api.Test;

import java.io.IOException;

public class ExtractCertTest {

    @Test
    public void extractCertFromFreshKey() throws IOException {
        BcSOP sop = new BcSOP();
        sop.extractCert()
                .key(sop.generateKey().userId("Alice <alice@example.org>").generate().getInputStream())
                .writeTo(System.out);
    }
}
