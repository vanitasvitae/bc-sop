package org.bcsop.sop;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.util.io.Streams;
import sop.Ready;
import sop.enums.ArmorLabel;
import sop.exception.SOPGPException;
import sop.operation.Armor;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public class BcArmor implements Armor {

    @Override
    public Armor label(ArmorLabel label) throws SOPGPException.UnsupportedOption {
        throw new SOPGPException.UnsupportedOption("labels are not supported.");
    }

    @Override
    public Ready data(InputStream data) throws SOPGPException.BadData, IOException {
        return new Ready() {
            @Override
            public void writeTo(OutputStream outputStream) throws IOException {
                ArmoredOutputStream armorOut = new ArmoredOutputStream(outputStream);
                Streams.pipeAll(data, armorOut);
                armorOut.close();
            }
        };
    }
}
