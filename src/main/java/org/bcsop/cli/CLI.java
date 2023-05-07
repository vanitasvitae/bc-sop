package org.bcsop.cli;

import org.bcsop.sop.BcSOP;
import sop.cli.picocli.SopCLI;

public class CLI extends SopCLI {

    public static void main(String[] args) {
        SopCLI.setSopInstance(new BcSOP());
        SopCLI.main(args);
    }
}
