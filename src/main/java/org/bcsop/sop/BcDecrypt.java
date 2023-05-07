package org.bcsop.sop;

import sop.DecryptionResult;
import sop.ReadyWithResult;
import sop.SessionKey;
import sop.exception.SOPGPException;
import sop.operation.Decrypt;

import java.io.IOException;
import java.io.InputStream;
import java.util.Date;

public class BcDecrypt implements Decrypt {

    @Override
    public Decrypt verifyNotBefore(Date timestamp) throws SOPGPException.UnsupportedOption {
        return null;
    }

    @Override
    public Decrypt verifyNotAfter(Date timestamp) throws SOPGPException.UnsupportedOption {
        return null;
    }

    @Override
    public Decrypt verifyWithCert(InputStream cert) throws SOPGPException.BadData, SOPGPException.UnsupportedAsymmetricAlgo, IOException {
        return null;
    }

    @Override
    public Decrypt withSessionKey(SessionKey sessionKey) throws SOPGPException.UnsupportedOption {
        return null;
    }

    @Override
    public Decrypt withPassword(String password) throws SOPGPException.PasswordNotHumanReadable, SOPGPException.UnsupportedOption {
        return null;
    }

    @Override
    public Decrypt withKey(InputStream key) throws SOPGPException.BadData, SOPGPException.UnsupportedAsymmetricAlgo, IOException {
        return null;
    }

    @Override
    public Decrypt withKeyPassword(byte[] password) throws SOPGPException.UnsupportedOption, SOPGPException.PasswordNotHumanReadable {
        return null;
    }

    @Override
    public ReadyWithResult<DecryptionResult> ciphertext(InputStream ciphertext) throws SOPGPException.BadData, SOPGPException.MissingArg, SOPGPException.CannotDecrypt, SOPGPException.KeyIsProtected, IOException {
        return null;
    }
}
