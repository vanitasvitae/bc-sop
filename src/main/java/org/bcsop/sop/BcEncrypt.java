package org.bcsop.sop;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.LiteralDataPacket;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.operator.PGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBEKeyEncryptionMethodGenerator;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;
import org.bouncycastle.util.io.Streams;
import sop.Ready;
import sop.enums.EncryptAs;
import sop.exception.SOPGPException;
import sop.operation.Encrypt;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Date;

public class BcEncrypt implements Encrypt {

    boolean armor = true;
    EncryptAs as = EncryptAs.Binary;

    PGPEncryptedDataGenerator encDataGen;
    PGPLiteralDataGenerator litDataGen;
    PGPSignatureGenerator sigGen = null;

    public BcEncrypt() {
        encDataGen = new PGPEncryptedDataGenerator(
                new BcPGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256));
        litDataGen = new PGPLiteralDataGenerator();
    }

    @Override
    public Encrypt noArmor() {
        this.armor = false;
        return this;
    }

    @Override
    public Encrypt mode(EncryptAs mode) throws SOPGPException.UnsupportedOption {
        this.as = mode;
        return this;
    }

    @Override
    public Encrypt signWith(InputStream key)
            throws SOPGPException.KeyCannotSign, SOPGPException.UnsupportedAsymmetricAlgo, SOPGPException.BadData, IOException {
        return this;
    }

    @Override
    public Encrypt withKeyPassword(byte[] password)
            throws SOPGPException.PasswordNotHumanReadable, SOPGPException.UnsupportedOption {
        return null;
    }

    @Override
    public Encrypt withPassword(String password)
            throws SOPGPException.PasswordNotHumanReadable, SOPGPException.UnsupportedOption {
        encDataGen.addMethod(new JcePBEKeyEncryptionMethodGenerator(password.toCharArray()));
        return this;
    }

    @Override
    public Encrypt withCert(InputStream cert)
            throws SOPGPException.CertCannotEncrypt, SOPGPException.UnsupportedAsymmetricAlgo, SOPGPException.BadData, IOException {
        PGPPublicKeyRing publicKeys = new PGPPublicKeyRing(cert, new JcaKeyFingerprintCalculator());
        for (PGPPublicKey key : publicKeys) {
            if (key.isEncryptionKey()) {
                encDataGen.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(key));
            }
        }
        return this;
    }

    @Override
    public Encrypt profile(String profileName) {
        throw new SOPGPException.UnsupportedProfile(profileName);
    }

    @Override
    public Ready plaintext(InputStream plaintext)
            throws IOException, SOPGPException.KeyIsProtected {
        return new Ready() {
            @Override
            public void writeTo(OutputStream outputStream) throws IOException {
                OutputStream out = armor ? new ArmoredOutputStream(outputStream) : outputStream;
                try {
                    OutputStream encOut = encDataGen.open(out, new byte[2 << 8]);
                    OutputStream litOut = litDataGen.open(
                            encOut,
                            as == EncryptAs.Binary ? PGPLiteralData.BINARY : PGPLiteralData.TEXT,
                            "",
                            new Date()
                            , new byte[2 << 8]);
                    Streams.pipeAll(plaintext, litOut);
                    litOut.close();
                    encOut.close();
                    out.close();
                } catch (PGPException e) {
                    throw new RuntimeException(e);
                }
            }
        };
    }
}
