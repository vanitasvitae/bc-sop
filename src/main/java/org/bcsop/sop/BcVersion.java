package org.bcsop.sop;

import sop.operation.Version;

public class BcVersion implements Version {
    @Override
    public String getName() {
        return "BcSOP";
    }

    @Override
    public String getVersion() {
        return "0.1.0";
    }

    @Override
    public String getBackendVersion() {
        return "Vanilla Bouncy Castle 1.73";
    }

    @Override
    public String getExtendedVersion() {
        return "A SOP implementation using naive Bouncycastle.";
    }

    @Override
    public int getSopSpecRevisionNumber() {
        return 6;
    }

    @Override
    public boolean isSopSpecImplementationIncomplete() {
        return true;
    }

    @Override
    public String getSopSpecImplementationRemarks() {
        return null;
    }
}
