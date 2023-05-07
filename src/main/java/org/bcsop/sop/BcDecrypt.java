package org.bcsop.sop;

import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPOnePassSignature;
import org.bouncycastle.openpgp.PGPOnePassSignatureList;
import org.bouncycastle.openpgp.PGPPBEEncryptedData;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSessionKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.PBEDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcePBEDataDecryptorFactoryBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JceSessionKeyDataDecryptorFactoryBuilder;
import org.bouncycastle.util.encoders.Hex;
import sop.DecryptionResult;
import sop.ReadyWithResult;
import sop.SessionKey;
import sop.Verification;
import sop.exception.SOPGPException;
import sop.operation.Decrypt;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

public class BcDecrypt implements Decrypt {

    Date notBefore;
    Date notAfter;

    private final List<PGPPublicKeyRing> certs = new ArrayList<>();
    private final List<PGPSecretKeyRing> keys = new ArrayList<>();
    private final List<byte[]> keyPasswords = new ArrayList<>();
    private final List<SessionKey> sessionKeys = new ArrayList<>();
    private final List<String> passwords = new ArrayList<>();

    @Override
    public Decrypt verifyNotBefore(Date timestamp)
            throws SOPGPException.UnsupportedOption {
        this.notBefore = timestamp;
        return this;
    }

    @Override
    public Decrypt verifyNotAfter(Date timestamp)
            throws SOPGPException.UnsupportedOption {
        this.notAfter = timestamp;
        return this;
    }

    @Override
    public Decrypt verifyWithCert(InputStream cert)
            throws SOPGPException.BadData, SOPGPException.UnsupportedAsymmetricAlgo, IOException {
        PGPPublicKeyRing c = new PGPPublicKeyRing(
                PGPUtil.getDecoderStream(cert),
                new JcaKeyFingerprintCalculator());
        this.certs.add(c);
        return this;
    }

    @Override
    public Decrypt withSessionKey(SessionKey sessionKey)
            throws SOPGPException.UnsupportedOption {
        this.sessionKeys.add(sessionKey);
        return this;
    }

    @Override
    public Decrypt withPassword(String password)
            throws SOPGPException.PasswordNotHumanReadable, SOPGPException.UnsupportedOption {
        this.passwords.add(password);
        return this;
    }

    @Override
    public Decrypt withKey(InputStream key)
            throws SOPGPException.BadData, SOPGPException.UnsupportedAsymmetricAlgo, IOException {
        try {
            PGPSecretKeyRing secretKeys = new PGPSecretKeyRing(
                    PGPUtil.getDecoderStream(key),
                    new JcaKeyFingerprintCalculator());
            keys.add(secretKeys);
        } catch (PGPException e) {
            throw new SOPGPException.BadData(e);
        }
        return this;
    }

    @Override
    public Decrypt withKeyPassword(byte[] password)
            throws SOPGPException.UnsupportedOption, SOPGPException.PasswordNotHumanReadable {
        this.keyPasswords.add(password);
        return this;
    }

    @Override
    public ReadyWithResult<DecryptionResult> ciphertext(InputStream ciphertext)
            throws SOPGPException.BadData, SOPGPException.MissingArg, SOPGPException.CannotDecrypt, SOPGPException.KeyIsProtected, IOException {
        return new ReadyWithResult<DecryptionResult>() {
            @Override
            public DecryptionResult writeTo(OutputStream outputStream) throws IOException, SOPGPException.NoSignature {

                PGPPublicKeyRingCollection certificates = new PGPPublicKeyRingCollection(certs);

                List<SignatureVerification> signatures = new ArrayList<>();
                PGPSessionKey sessionKey = null;

                InputStream inputStream = PGPUtil.getDecoderStream(ciphertext);
                PGPObjectFactory objectFactory = new JcaPGPObjectFactory(inputStream);
                List<SignatureVerification> validSignatures = new ArrayList<>();
                Object next;
                while ((next = objectFactory.nextObject()) != null) {
                    if (next instanceof PGPOnePassSignatureList) {
                        PGPOnePassSignatureList opsList = (PGPOnePassSignatureList) next;
                        for (PGPOnePassSignature ops : opsList) {
                            PGPPublicKeyRing cert = certificates.getPublicKeyRing(ops.getKeyID());
                            if (cert == null) {
                                continue;
                            }

                            try {
                                ops.init(new JcaPGPContentVerifierBuilderProvider(), cert.getPublicKey(ops.getKeyID()));
                                signatures.add(new SignatureVerification(ops, cert));
                            } catch (PGPException e) {
                                throw new RuntimeException(e);
                            }
                        }
                    }

                    if (next instanceof PGPSignatureList) {
                        PGPSignatureList sigList = (PGPSignatureList) next;
                        for (SignatureVerification verification : signatures) {
                            PGPSignature signature = null;
                            for (PGPSignature sig : sigList) {
                                if (verification.getOps().getKeyID() == sig.getKeyID()) {
                                    signature = sig;
                                }
                            }

                            if (signature == null) {
                                continue;
                            }

                            if (notAfter != null && signature.getCreationTime().after(notAfter)) {
                                continue;
                            }

                            if (notBefore != null && signature.getCreationTime().before(notBefore)) {
                                continue;
                            }

                            try {
                                if (verification.getOps().verify(signature)) {
                                    verification.setSignature(signature);
                                    validSignatures.add(verification);
                                }
                            } catch (PGPException e) {
                                continue;
                            }
                        }
                    }

                    if (next instanceof PGPLiteralData) {
                        PGPLiteralData literalData = (PGPLiteralData) next;
                        InputStream plaintext = literalData.getDataStream();
                        int ch;
                        while ((ch = plaintext.read()) >= 0) {
                            outputStream.write(ch);
                            for (SignatureVerification ops : signatures) {
                                ops.getOps().update((byte) ch);
                            }
                        }
                    }

                    if (next instanceof PGPCompressedData) {
                        PGPCompressedData compressedData = (PGPCompressedData) next;
                        try {
                            inputStream = compressedData.getDataStream();
                            objectFactory = new JcaPGPObjectFactory(inputStream);
                        } catch (PGPException e) {
                            throw new RuntimeException(e);
                        }
                    }

                    if (next instanceof PGPEncryptedDataList) {
                        PGPEncryptedDataList encDataList = (PGPEncryptedDataList) next;
                        for (PGPEncryptedData encData : encDataList) {

                            if (encData instanceof PGPPublicKeyEncryptedData) {
                                PGPPublicKeyEncryptedData pkEncData = (PGPPublicKeyEncryptedData) encData;
                                for (PGPSecretKeyRing secretKeys : keys) {
                                    if (secretKeys.getPublicKey(pkEncData.getKeyID()) == null) {
                                        continue;
                                    }

                                    PGPSecretKey secretKey = secretKeys.getSecretKey(pkEncData.getKeyID());
                                    PGPPrivateKey privateKey;
                                    try {
                                        privateKey = BcUtil.unlock(secretKey, keyPasswords);
                                    } catch (PGPException e) {
                                        throw new SOPGPException.KeyIsProtected("Cannot unlock secret key", e);
                                    }

                                    try {
                                        sessionKey = pkEncData.getSessionKey(new JcePublicKeyDataDecryptorFactoryBuilder().build(privateKey));
                                        inputStream = encDataList.extractSessionKeyEncryptedData()
                                                .getDataStream(new JceSessionKeyDataDecryptorFactoryBuilder()
                                                        .build(sessionKey));
                                        objectFactory = new JcaPGPObjectFactory(inputStream);
                                    } catch (PGPException e) {
                                        continue;
                                    }
                                }
                            } else {
                                PGPPBEEncryptedData pbEncData = (PGPPBEEncryptedData) encData;
                                for (String password : passwords) {
                                    PBEDataDecryptorFactory decryptorFactory = new JcePBEDataDecryptorFactoryBuilder().build(password.toCharArray());
                                    try {
                                        sessionKey = pbEncData.getSessionKey(decryptorFactory);
                                        inputStream = encDataList.extractSessionKeyEncryptedData()
                                                .getDataStream(new JceSessionKeyDataDecryptorFactoryBuilder()
                                                        .build(sessionKey));
                                        objectFactory = new JcaPGPObjectFactory(inputStream);
                                        break;
                                    } catch (PGPException e) {
                                        throw new RuntimeException(e);
                                    }
                                }
                            }
                        }
                    }
                }

                List<Verification> verifications = new ArrayList<>();
                for (SignatureVerification validSig : validSignatures) {
                    verifications.add(new Verification(
                            validSig.getSignature().getCreationTime(),
                            Hex.toHexString(validSig.getCert().getPublicKey(validSig.getSignature().getKeyID()).getFingerprint()),
                            Hex.toHexString(validSig.getCert().getPublicKey().getFingerprint())));
                }
                return new DecryptionResult(new SessionKey((byte) sessionKey.getAlgorithm(), sessionKey.getKey()), verifications);
            }
        };
    }

}
