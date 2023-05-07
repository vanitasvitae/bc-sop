package org.bcsop.sop;

import sop.Profile;
import sop.operation.ListProfiles;

import java.util.Collections;
import java.util.List;

public class BcListProfiles implements ListProfiles {

    @Override
    public List<Profile> subcommand(String command) {
        return Collections.emptyList();
    }
}
