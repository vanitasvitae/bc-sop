package org.bcsop.sop;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPKeyRingGenerator;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptor;
import org.bouncycastle.openpgp.operator.PGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder;
import sop.Ready;
import sop.exception.SOPGPException;
import sop.operation.GenerateKey;

import java.io.IOException;
import java.io.OutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

public class BcGenerateKey implements GenerateKey {

    private boolean armor = true;
    private final List<String> userIds = new ArrayList<>();
    private String password = null;

    @Override
    public GenerateKey noArmor() {
        armor = false;
        return this;
    }

    @Override
    public GenerateKey userId(String userId) {
        userIds.add(userId);
        return this;
    }

    @Override
    public GenerateKey withKeyPassword(String password) throws SOPGPException.PasswordNotHumanReadable, SOPGPException.UnsupportedOption {
        this.password = password;
        return this;
    }

    @Override
    public GenerateKey profile(String profile) {
        throw new SOPGPException.UnsupportedProfile(profile);
    }

    @Override
    public Ready generate() throws SOPGPException.MissingArg, SOPGPException.UnsupportedAsymmetricAlgo {
        return new Ready() {
            @Override
            public void writeTo(OutputStream outputStream) throws IOException {
                OutputStream secretOut = armor ? new ArmoredOutputStream(outputStream) : outputStream;
                try {
                    PGPSecretKeyRing secretKeys = generateKey();
                    secretKeys.encode(secretOut);
                    secretOut.close();
                } catch (PGPException e) {
                    throw new RuntimeException(e);
                }
            }
        };
    }

    private PGPSecretKeyRing generateKey() throws PGPException {
        KeyPairGenerator kpg;
        try {
            kpg = KeyPairGenerator.getInstance("RSA", "BC");
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new RuntimeException(e);
        }

        kpg.initialize(3072);

        KeyPair kp = kpg.generateKeyPair();

        PGPDigestCalculator sha1Calc = new JcaPGPDigestCalculatorProviderBuilder()
                .setProvider(BcSOP.PROVIDER)
                .build().get(HashAlgorithmTags.SHA1);
        PGPContentSignerBuilder signerBuilder = new JcaPGPContentSignerBuilder(
                PublicKeyAlgorithmTags.RSA_GENERAL, HashAlgorithmTags.SHA384)
                .setProvider(BcSOP.PROVIDER);
        JcePBESecretKeyEncryptorBuilder encBuilder = new JcePBESecretKeyEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256)
                .setProvider(BcSOP.PROVIDER);
        PBESecretKeyEncryptor encryptor = password == null ? null : encBuilder.build(password.toCharArray());
        PGPKeyPair keyPair = new JcaPGPKeyPair(PGPPublicKey.RSA_GENERAL, kp, new Date());
        PGPKeyRingGenerator ringGen;
        if (userIds.isEmpty()) {
            ringGen = new PGPKeyRingGenerator(keyPair, sha1Calc, null, null, signerBuilder, encryptor);
        } else {
            ringGen = new PGPKeyRingGenerator(PGPSignature.DEFAULT_CERTIFICATION, keyPair, userIds.get(0), sha1Calc, null, null, signerBuilder, encryptor);
        }

        return ringGen.generateSecretKeyRing();
    }
}
