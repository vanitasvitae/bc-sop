package org.bcsop.sop;


import org.bouncycastle.openpgp.PGPOnePassSignature;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSignature;

public class SignatureVerification {
    private final PGPOnePassSignature ops;
    private final PGPPublicKeyRing cert;
    private PGPSignature signature;

    public SignatureVerification(PGPOnePassSignature ops, PGPPublicKeyRing cert) {
        this.ops = ops;
        this.cert = cert;
    }

    public SignatureVerification(PGPSignature signature, PGPPublicKeyRing cert) {
        this.ops = null;
        this.cert = cert;
        this.signature = signature;
    }

    public PGPOnePassSignature getOps() {
        return ops;
    }

    public PGPPublicKeyRing getCert() {
        return cert;
    }

    public PGPSignature getSignature() {
        return signature;
    }

    public void setSignature(PGPSignature signature) {
        this.signature = signature;
    }
}