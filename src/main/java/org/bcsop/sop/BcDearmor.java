package org.bcsop.sop;

import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.util.io.Streams;
import sop.Ready;
import sop.exception.SOPGPException;
import sop.operation.Dearmor;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public class BcDearmor implements Dearmor {
    @Override
    public Ready data(InputStream data) throws SOPGPException.BadData, IOException {
        return new Ready() {
            @Override
            public void writeTo(OutputStream outputStream) throws IOException {
                ArmoredInputStream armorIn = new ArmoredInputStream(data);
                Streams.pipeAll(armorIn, outputStream);
                armorIn.close();
            }
        };
    }
}
