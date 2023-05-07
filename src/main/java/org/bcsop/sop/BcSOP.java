package org.bcsop.sop;

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

public class BcSOP implements SOP {
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
        return null;
    }

    @Override
    public InlineSign inlineSign() {
        return null;
    }

    @Override
    public DetachedVerify detachedVerify() {
        return null;
    }

    @Override
    public InlineVerify inlineVerify() {
        return null;
    }

    @Override
    public InlineDetach inlineDetach() {
        return null;
    }

    @Override
    public Encrypt encrypt() {
        return null;
    }

    @Override
    public Decrypt decrypt() {
        return null;
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
