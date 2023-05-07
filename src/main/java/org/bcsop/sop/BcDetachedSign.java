package org.bcsop.sop;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import sop.MicAlg;
import sop.ReadyWithResult;
import sop.SigningResult;
import sop.enums.SignAs;
import sop.exception.SOPGPException;
import sop.operation.DetachedSign;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.List;

public class BcDetachedSign implements DetachedSign {

    private boolean armor = true;
    private SignAs as = SignAs.Binary;
    private final List<PGPSecretKeyRing> signingKeys = new ArrayList<>();
    private final List<byte[]> keyPasswords = new ArrayList<>();

    @Override
    public DetachedSign mode(SignAs mode) throws SOPGPException.UnsupportedOption {
        this.as = mode;
        return this;
    }

    @Override
    public ReadyWithResult<SigningResult> data(InputStream data) throws IOException, SOPGPException.KeyIsProtected, SOPGPException.ExpectedText {
        List<PGPSignatureGenerator> sigGens = new ArrayList<>();
        for (PGPSecretKeyRing secretKeys : signingKeys) {
            for (PGPSecretKey key : secretKeys) {
                if (key.isSigningKey()) {
                    try {
                        PGPPrivateKey privateKey = BcUtil.unlock(key, keyPasswords);
                        JcaPGPContentSignerBuilder sigBuilder = new JcaPGPContentSignerBuilder(
                                key.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA384)
                                .setProvider(BcSOP.PROVIDER);
                        PGPSignatureGenerator sigGen = new PGPSignatureGenerator(sigBuilder);
                        sigGen.init(
                                as == SignAs.Binary ? PGPSignature.BINARY_DOCUMENT : PGPSignature.CANONICAL_TEXT_DOCUMENT,
                                privateKey);
                        sigGens.add(sigGen);
                    } catch (PGPException e) {
                        throw new RuntimeException(e);
                    }
                }
            }
        }

        int ch;
        while ((ch = data.read()) >= 0) {
            for (PGPSignatureGenerator sigGen : sigGens) {
                sigGen.update((byte) ch);
            }
        }

        return new ReadyWithResult<SigningResult>() {
            @Override
            public SigningResult writeTo(OutputStream outputStream) throws IOException, SOPGPException.NoSignature {
                OutputStream out = armor ? new ArmoredOutputStream(outputStream) : outputStream;
                for (PGPSignatureGenerator sigGen : sigGens) {
                    try {
                        sigGen.generate().encode(out);
                    } catch (PGPException e) {
                        throw new RuntimeException(e);
                    }
                }
                out.close();

                return new SigningResult.Builder()
                        .setMicAlg(MicAlg.fromHashAlgorithmId(HashAlgorithmTags.SHA384))
                        .build();
            }
        };
    }

    @Override
    public DetachedSign noArmor() {
        armor = false;
        return this;
    }

    @Override
    public DetachedSign key(InputStream key) throws SOPGPException.KeyCannotSign, SOPGPException.BadData, SOPGPException.UnsupportedAsymmetricAlgo, IOException {
        try {
            PGPSecretKeyRing secretKeys = new PGPSecretKeyRing(
                    PGPUtil.getDecoderStream(key),
                    new JcaKeyFingerprintCalculator().setProvider(BcSOP.PROVIDER));
            signingKeys.add(secretKeys);
        } catch (PGPException e) {
            throw new SOPGPException.BadData(e);
        }
        return this;
    }

    @Override
    public DetachedSign withKeyPassword(byte[] password) throws SOPGPException.UnsupportedOption, SOPGPException.PasswordNotHumanReadable {
        this.keyPasswords.add(password);
        return this;
    }
}
