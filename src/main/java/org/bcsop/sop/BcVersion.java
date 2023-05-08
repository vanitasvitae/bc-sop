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
        return "Naiive Bouncy Castle 1.73";
    }

    @Override
    public String getExtendedVersion() {
        return "A naiive SOP implementation using Bouncy Castle.";
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
