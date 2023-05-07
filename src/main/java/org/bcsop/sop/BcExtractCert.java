package org.bcsop.sop;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import sop.Ready;
import sop.exception.SOPGPException;
import sop.operation.ExtractCert;

import javax.swing.plaf.basic.BasicCheckBoxUI;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

public class BcExtractCert implements ExtractCert {

    boolean armor = true;

    @Override
    public ExtractCert noArmor() {
        this.armor = false;
        return this;
    }

    @Override
    public Ready key(InputStream keyInputStream) throws IOException, SOPGPException.BadData {
        try {
            PGPSecretKeyRing secretKeys = new PGPSecretKeyRing(
                    PGPUtil.getDecoderStream(keyInputStream),
                    new JcaKeyFingerprintCalculator());
            Iterator< PGPPublicKey> it = secretKeys.getPublicKeys();
            List<PGPPublicKey> list = new ArrayList<>();
            while (it.hasNext()) {
                list.add(it.next());
            }
            it = secretKeys.getExtraPublicKeys();
            while (it.hasNext()) {
                list.add(it.next());
            }
            PGPPublicKeyRing publicKeys = new PGPPublicKeyRing(list);
            return new Ready() {
                @Override
                public void writeTo(OutputStream outputStream) throws IOException {
                    OutputStream out = armor ? new ArmoredOutputStream(outputStream) : outputStream;
                    publicKeys.encode(out);
                    out.close();
                }
            };
        } catch (PGPException e) {
            throw new SOPGPException.BadData(e);
        }
    }
}
