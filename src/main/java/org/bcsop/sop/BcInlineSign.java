package org.bcsop.sop;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.PGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import sop.Ready;
import sop.enums.InlineSignAs;
import sop.exception.SOPGPException;
import sop.operation.InlineSign;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

public class BcInlineSign implements InlineSign {

    private boolean armor = true;
    private InlineSignAs as = InlineSignAs.binary;
    private final List<byte[]> keyPasswords = new ArrayList<>();
    private final List<PGPSecretKeyRing> signingKeys = new ArrayList<>();

    @Override
    public InlineSign mode(InlineSignAs mode)
            throws SOPGPException.UnsupportedOption {
        this.as = mode;
        return this;
    }

    @Override
    public Ready data(InputStream data)
            throws IOException, SOPGPException.KeyIsProtected, SOPGPException.ExpectedText {
        return new Ready() {
            @Override
            public void writeTo(OutputStream outputStream) throws IOException {
                List<PGPSignatureGenerator> sigGens = new ArrayList<>();
                for (PGPSecretKeyRing signingKey : signingKeys) {
                    for (PGPSecretKey key : signingKey) {
                        if (!key.isSigningKey()) {
                            continue;
                        }

                        try {
                            PGPPrivateKey privateKey = BcUtil.unlock(key, keyPasswords);
                            PGPContentSignerBuilder sigBuilder = new JcaPGPContentSignerBuilder(
                                    key.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA384)
                                    .setProvider(BcSOP.PROVIDER);
                            PGPSignatureGenerator sigGen = new PGPSignatureGenerator(sigBuilder);
                            sigGen.init(
                                    as == InlineSignAs.binary ? PGPSignature.BINARY_DOCUMENT : PGPSignature.CANONICAL_TEXT_DOCUMENT,
                                    privateKey);
                            sigGens.add(sigGen);
                        } catch (PGPException e) {
                            continue;
                        }
                    }
                }

                if (as == InlineSignAs.clearsigned) {
                    ArmoredOutputStream out = new ArmoredOutputStream(outputStream);
                    out.beginClearText(HashAlgorithmTags.SHA384);
                    int ch;
                    while ((ch = data.read()) >= 0) {
                        out.write(ch);
                        for (PGPSignatureGenerator sigGen : sigGens) {
                            sigGen.update((byte) ch);
                        }
                    }

                    out.endClearText();
                    for (PGPSignatureGenerator sigGen : sigGens) {
                        try {
                            sigGen.generate().encode(out);
                        } catch (PGPException e) {
                            throw new RuntimeException(e);
                        }
                    }
                    out.close();
                } else {
                    try {
                        OutputStream out = armor ? new ArmoredOutputStream(outputStream) : outputStream;
                        for (PGPSignatureGenerator sigGen : sigGens) {
                            sigGen.generateOnePassVersion(false).encode(out);
                        }
                        PGPLiteralDataGenerator litGen = new PGPLiteralDataGenerator();
                        OutputStream litOut = litGen.open(out,
                                as == InlineSignAs.text ? PGPLiteralData.TEXT : PGPLiteralData.BINARY,
                                "", new Date(), new byte[2 << 8]);
                        int ch;
                        while ((ch = data.read()) >= 0) {
                            litOut.write(ch);
                            for (PGPSignatureGenerator sigGen : sigGens) {
                                sigGen.update((byte) ch);
                            }
                        }

                        litOut.close();

                        for (int i = sigGens.size() - 1; i >= 0; i--) {
                            sigGens.get(i).generate().encode(out);
                        }

                        out.close();
                    } catch (PGPException e) {
                        throw new RuntimeException(e);
                    }
                }
            }
        };
    }

    @Override
    public InlineSign noArmor() {
        armor = false;
        return this;
    }

    @Override
    public InlineSign key(InputStream key)
            throws SOPGPException.KeyCannotSign, SOPGPException.BadData, SOPGPException.UnsupportedAsymmetricAlgo, IOException {
        try {
            PGPSecretKeyRing secretKeys = new PGPSecretKeyRing(
                    PGPUtil.getDecoderStream(key), new JcaKeyFingerprintCalculator().setProvider(BcSOP.PROVIDER));
            signingKeys.add(secretKeys);
        } catch (PGPException e) {
            throw new SOPGPException.BadData("Cannot read key", e);
        }
        return this;
    }

    @Override
    public InlineSign withKeyPassword(byte[] password)
            throws SOPGPException.UnsupportedOption, SOPGPException.PasswordNotHumanReadable {
        this.keyPasswords.add(password);
        return this;
    }
}
