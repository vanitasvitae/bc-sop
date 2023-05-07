package org.bcsop.sop;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider;
import org.bouncycastle.util.encoders.Hex;
import sop.Verification;
import sop.exception.SOPGPException;
import sop.operation.DetachedVerify;
import sop.operation.VerifySignatures;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

public class BcDetachedVerify implements DetachedVerify {

    private Date notBefore;
    private Date notAfter;
    private PGPSignatureList signatures;
    private final List<PGPPublicKeyRing> certs = new ArrayList<>();

    @Override
    public VerifySignatures signatures(InputStream signaturesIn) throws SOPGPException.BadData, IOException {
        InputStream decoderStream = PGPUtil.getDecoderStream(signaturesIn);
        PGPObjectFactory objectFactory = new JcaPGPObjectFactory(decoderStream);
        Object next;
        while ((next = objectFactory.nextObject()) != null) {
            if (next instanceof PGPSignatureList) {
                signatures = (PGPSignatureList) next;
                return this;
            }

            if (next instanceof PGPSignature) {
                signatures = new PGPSignatureList((PGPSignature) next);
                return this;
            }
        }

        throw new SOPGPException.BadData("No Signatures found");
    }

    @Override
    public DetachedVerify notBefore(Date timestamp) throws SOPGPException.UnsupportedOption {
        this.notBefore = timestamp;
        return this;
    }

    @Override
    public DetachedVerify notAfter(Date timestamp) throws SOPGPException.UnsupportedOption {
        this.notAfter = timestamp;
        return this;
    }

    @Override
    public DetachedVerify cert(InputStream cert) throws SOPGPException.BadData, IOException {
        PGPPublicKeyRing publicKeys = new PGPPublicKeyRing(PGPUtil.getDecoderStream(cert), new JcaKeyFingerprintCalculator());
        certs.add(publicKeys);
        return this;
    }

    @Override
    public List<Verification> data(InputStream data) throws IOException, SOPGPException.NoSignature, SOPGPException.BadData {
        PGPPublicKeyRingCollection certificates = new PGPPublicKeyRingCollection(certs);
        List<SignatureVerification> verifications = new ArrayList<>();
        for (PGPSignature signature : signatures) {
            PGPPublicKeyRing issuer = certificates.getPublicKeyRing(signature.getKeyID());
            if (issuer == null) {
                continue;
            }

            if (notBefore != null && signature.getCreationTime().before(notBefore)) {
                continue;
            }

            if (notAfter != null && signature.getCreationTime().after(notAfter)) {
                continue;
            }

            try {
                signature.init(new JcaPGPContentVerifierBuilderProvider()
                        .setProvider(new BouncyCastleProvider()),
                        issuer.getPublicKey(signature.getKeyID()));
                SignatureVerification verification = new SignatureVerification(signature, issuer);
                verifications.add(verification);
            } catch (PGPException e) {
                continue;
            }
        }

        int ch;
        while ((ch = data.read()) >= 0) {
            for (SignatureVerification verification : verifications) {
                verification.getSignature().update((byte) ch);
            }
        }

        List<Verification> validVerifications = new ArrayList<>();
        for (SignatureVerification verification : verifications) {
            try {
                if (verification.getSignature().verify()) {
                    validVerifications.add(new Verification(
                            verification.getSignature().getCreationTime(),
                            Hex.toHexString(verification.getCert().getPublicKey(verification.getSignature().getKeyID()).getFingerprint()),
                            Hex.toHexString(verification.getCert().getPublicKey().getFingerprint())
                    ));
                }
            } catch (PGPException e) {
                //
            }
        }

        return validVerifications;
    }
}
