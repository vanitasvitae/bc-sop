package org.bcsop.sop;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import sop.SOP;
import sop.operation.Armor;
import sop.operation.Dearmor;
import sop.operation.Decrypt;
import sop.operation.DetachedSign;
import sop.operation.DetachedVerify;
import sop.operation.Encrypt;
import sop.operation.ExtractCert;
import sop.operation.GenerateKey;
import sop.operation.InlineDetach;
import sop.operation.InlineSign;
import sop.operation.InlineVerify;
import sop.operation.ListProfiles;
import sop.operation.Version;

import java.security.Security;

public class BcSOP implements SOP {

    static final BouncyCastleProvider PROVIDER = new BouncyCastleProvider();

    public BcSOP() {
        Security.insertProviderAt(PROVIDER, 1);
    }

    @Override
    public Version version() {
        return new BcVersion();
    }

    @Override
    public GenerateKey generateKey() {
        return new BcGenerateKey();
    }

    @Override
    public ExtractCert extractCert() {
        return new BcExtractCert();
    }

    @Override
    public DetachedSign detachedSign() {
        return new BcDetachedSign();
    }

    @Override
    public InlineSign inlineSign() {
        return new BcInlineSign();
    }

    @Override
    public DetachedVerify detachedVerify() {
        return new BcDetachedVerify();
    }

    @Override
    public InlineVerify inlineVerify() {
        return new BcInlineVerify();
    }

    @Override
    public InlineDetach inlineDetach() {
        return new BcInlineDetach();
    }

    @Override
    public Encrypt encrypt() {
        return new BcEncrypt();
    }

    @Override
    public Decrypt decrypt() {
        return new BcDecrypt();
    }

    @Override
    public Armor armor() {
        return new BcArmor();
    }

    @Override
    public Dearmor dearmor() {
        return new BcDearmor();
    }

    @Override
    public ListProfiles listProfiles() {
        return new BcListProfiles();
    }
}
