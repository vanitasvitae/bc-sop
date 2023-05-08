package org.bcsop.sop;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPOnePassSignature;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.PGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBEKeyEncryptionMethodGenerator;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;
import sop.Ready;
import sop.enums.EncryptAs;
import sop.exception.SOPGPException;
import sop.operation.Encrypt;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

public class BcEncrypt implements Encrypt {

    boolean armor = true;
    EncryptAs as = EncryptAs.Binary;

    PGPEncryptedDataGenerator encDataGen;
    PGPLiteralDataGenerator litDataGen;

    private final List<PGPSecretKeyRing> signingKeys = new ArrayList<>();
    private final List<byte[]> keyPasswords = new ArrayList<>();

    public BcEncrypt() {
        encDataGen = new PGPEncryptedDataGenerator(
                new JcePGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256)
                        .setProvider(BcSOP.PROVIDER));
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
        try {
            PGPSecretKeyRing secretKeys = new PGPSecretKeyRing(
                    PGPUtil.getDecoderStream(key),
                    new JcaKeyFingerprintCalculator().setProvider(BcSOP.PROVIDER));
            signingKeys.add(secretKeys);
        } catch (PGPException e) {
            throw new RuntimeException(e);
        }
        return this;
    }

    @Override
    public Encrypt withKeyPassword(byte[] password)
            throws SOPGPException.PasswordNotHumanReadable, SOPGPException.UnsupportedOption {
        this.keyPasswords.add(password);
        return this;
    }

    @Override
    public Encrypt withPassword(String password)
            throws SOPGPException.PasswordNotHumanReadable, SOPGPException.UnsupportedOption {
        encDataGen.addMethod(new JcePBEKeyEncryptionMethodGenerator(password.toCharArray())
                .setProvider(BcSOP.PROVIDER));
        return this;
    }

    @Override
    public Encrypt withCert(InputStream cert)
            throws SOPGPException.CertCannotEncrypt, SOPGPException.UnsupportedAsymmetricAlgo, SOPGPException.BadData, IOException {
        PGPPublicKeyRing publicKeys = new PGPPublicKeyRing(
                PGPUtil.getDecoderStream(cert),
                new JcaKeyFingerprintCalculator().setProvider(BcSOP.PROVIDER));
        for (PGPPublicKey key : publicKeys) {
            if (key.isEncryptionKey()) {
                encDataGen.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(key)
                        .setProvider(BcSOP.PROVIDER));
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

                List<PGPSignatureGenerator> sigGens = new ArrayList<>();
                for (PGPSecretKeyRing signingKey : signingKeys) {
                    for (PGPSecretKey key : signingKey) {
                        try {
                            if (key.isSigningKey()) {
                                PGPPrivateKey privateKey = BcUtil.unlock(key, keyPasswords);
                                PGPContentSignerBuilder sigBuilder = new JcaPGPContentSignerBuilder(
                                        key.getPublicKey().getAlgorithm(),
                                        HashAlgorithmTags.SHA384).setProvider(BcSOP.PROVIDER);
                                PGPSignatureGenerator sigGen = new PGPSignatureGenerator(sigBuilder);
                                sigGen.init(
                                        as == EncryptAs.Binary ? PGPSignature.BINARY_DOCUMENT : PGPSignature.CANONICAL_TEXT_DOCUMENT,
                                        privateKey);
                                sigGens.add(sigGen);
                            }
                        } catch (PGPException e) {
                            throw new SOPGPException.BadData("Cannot unlock secret key.", e);
                        }
                    }
                }

                try {
                    OutputStream encOut = encDataGen.open(out, new byte[2 << 8]);
                    for (PGPSignatureGenerator sigGen : sigGens) {
                        PGPOnePassSignature ops = sigGen.generateOnePassVersion(false);
                        ops.encode(encOut);
                    }
                    OutputStream litOut = litDataGen.open(
                            encOut,
                            as == EncryptAs.Binary ? PGPLiteralData.BINARY : PGPLiteralData.TEXT,
                            "",
                            new Date()
                            , new byte[2 << 8]);

                    int ch;
                    while ((ch = plaintext.read()) >= 0) {
                        for (PGPSignatureGenerator sigGen : sigGens) {
                            sigGen.update((byte) ch);
                        }
                        litOut.write((byte) ch);
                    }
                    litOut.flush();
                    litOut.close();

                    for (int i = sigGens.size() - 1; i >= 0; i--) {
                        sigGens.get(i).generate().encode(encOut);
                    }

                    encOut.flush();
                    encOut.close();
                    out.flush();
                    out.close();
                } catch (PGPException e) {
                    throw new RuntimeException(e);
                }
            }
        };
    }


}
