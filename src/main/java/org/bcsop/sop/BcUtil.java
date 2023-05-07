package org.bcsop.sop;

import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.bouncycastle.util.Strings;
import sop.exception.SOPGPException;

import java.util.List;

public class BcUtil {

    public static PGPPrivateKey unlock(PGPSecretKey key, List<byte[]> passwords) throws PGPException {
        JcePBESecretKeyDecryptorBuilder decryptorBuilder = new JcePBESecretKeyDecryptorBuilder().setProvider(BcSOP.PROVIDER);
        PBESecretKeyDecryptor decryptor;
        if (key.getKeyEncryptionAlgorithm() == SymmetricKeyAlgorithmTags.NULL) {
            decryptor = decryptorBuilder.build(null);
            return key.extractPrivateKey(decryptor);
        }

        for (byte[] passphrase : passwords) {
            char[] chars = Strings.asCharArray(passphrase);
            decryptor = decryptorBuilder.build(chars);
            try {
                return key.extractPrivateKey(decryptor);
            } catch (Exception e) {
                // continue
            }
        }

        throw new SOPGPException.KeyIsProtected("Key is protected.");
    }
}
