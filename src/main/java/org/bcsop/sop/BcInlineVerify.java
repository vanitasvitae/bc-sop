package org.bcsop.sop;

import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPOnePassSignature;
import org.bouncycastle.openpgp.PGPOnePassSignatureList;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider;
import org.bouncycastle.util.encoders.Hex;
import sop.ReadyWithResult;
import sop.Verification;
import sop.exception.SOPGPException;
import sop.operation.InlineVerify;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

public class BcInlineVerify implements InlineVerify {

    private Date notBefore;
    private Date notAfter;
    private final List<PGPPublicKeyRing> certs = new ArrayList<>();

    @Override
    public ReadyWithResult<List<Verification>> data(InputStream data)
            throws IOException, SOPGPException.NoSignature, SOPGPException.BadData {
        return new ReadyWithResult<List<Verification>>() {
            @Override
            public List<Verification> writeTo(OutputStream outputStream) throws IOException, SOPGPException.NoSignature {
                PGPPublicKeyRingCollection certificates = new PGPPublicKeyRingCollection(certs);

                InputStream decoder = PGPUtil.getDecoderStream(data);
                PGPObjectFactory objectFactory = new JcaPGPObjectFactory(decoder);

                List<SignatureVerification> verifications = new ArrayList<>();

                Object next;
                while ((next = objectFactory.nextObject()) != null) {
                    if (next instanceof PGPCompressedData) {
                        PGPCompressedData compressedData = (PGPCompressedData) next;
                        try {
                            decoder = compressedData.getDataStream();
                            objectFactory = new JcaPGPObjectFactory(decoder);
                            continue;
                        } catch (PGPException e) {
                            throw new SOPGPException.BadData(e);
                        }
                    }

                    if (next instanceof PGPLiteralData) {
                        PGPLiteralData literalData = (PGPLiteralData) next;
                        InputStream plainIn = literalData.getDataStream();
                        int ch;
                        while ((ch = plainIn.read()) >= 0) {
                            outputStream.write(ch);
                            for (SignatureVerification verification : verifications) {
                                verification.getOps().update((byte) ch);
                            }
                        }
                    }

                    if (next instanceof PGPOnePassSignatureList) {
                        PGPOnePassSignatureList opsList = (PGPOnePassSignatureList) next;
                        for (PGPOnePassSignature ops : opsList) {
                            PGPPublicKeyRing cert = certificates.getPublicKeyRing(ops.getKeyID());
                            if (cert == null) {
                                continue;
                            }

                            try {
                                ops.init(new JcaPGPContentVerifierBuilderProvider(), cert.getPublicKey(ops.getKeyID()));
                                verifications.add(new SignatureVerification(ops, cert));
                            } catch (PGPException e) {
                                continue;
                            }
                        }
                    }

                    if (next instanceof PGPSignatureList) {
                        PGPSignatureList signatureList = (PGPSignatureList) next;
                        for (PGPSignature signature : signatureList) {
                            for (SignatureVerification verification : verifications) {
                                if (verification.getOps().getKeyID() == signature.getKeyID()) {
                                    verification.setSignature(signature);
                                }
                            }
                        }
                    }
                }

                List<Verification> validVerifications = new ArrayList<>();
                for (SignatureVerification verification : verifications) {
                    if (verification.getSignature() == null) {
                        continue;
                    }

                    if (notAfter != null && verification.getSignature().getCreationTime().after(notAfter)) {
                        continue;
                    }

                    if (notBefore != null && verification.getSignature().getCreationTime().before(notBefore)) {
                        continue;
                    }

                    try {
                        if (verification.getOps().verify(verification.getSignature())) {
                            validVerifications.add(new Verification(verification.getSignature().getCreationTime(),
                                    Hex.toHexString(verification.getCert().getPublicKey(verification.getSignature().getKeyID()).getFingerprint()),
                                    Hex.toHexString(verification.getCert().getPublicKey().getFingerprint())));
                        }
                    } catch (PGPException e) {
                        continue;
                    }
                }

                return validVerifications;
            }
        };
    }

    @Override
    public InlineVerify notBefore(Date timestamp)
            throws SOPGPException.UnsupportedOption {
        this.notBefore = timestamp;
        return this;
    }

    @Override
    public InlineVerify notAfter(Date timestamp)
            throws SOPGPException.UnsupportedOption {
        this.notAfter = timestamp;
        return this;
    }

    @Override
    public InlineVerify cert(InputStream cert)
            throws SOPGPException.BadData, IOException {
        PGPPublicKeyRing publicKeys = new PGPPublicKeyRing(
                PGPUtil.getDecoderStream(cert), new JcaKeyFingerprintCalculator());
        certs.add(publicKeys);
        return this;
    }
}
