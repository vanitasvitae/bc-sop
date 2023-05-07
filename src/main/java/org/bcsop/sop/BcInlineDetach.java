package org.bcsop.sop;

import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.util.io.Streams;
import sop.ReadyWithResult;
import sop.Signatures;
import sop.exception.SOPGPException;
import sop.operation.InlineDetach;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public class BcInlineDetach implements InlineDetach {

    private boolean armor = true;

    @Override
    public InlineDetach noArmor() {
        this.armor = false;
        return this;
    }

    @Override
    public ReadyWithResult<Signatures> message(InputStream messageInputStream) throws IOException, SOPGPException.BadData {
        return new ReadyWithResult<Signatures>() {
            @Override
            public Signatures writeTo(OutputStream outputStream) throws IOException, SOPGPException.NoSignature {
                InputStream decoder = PGPUtil.getDecoderStream(messageInputStream);
                if (decoder instanceof ArmoredInputStream && ((ArmoredInputStream) decoder).isClearText()) {
                    ArmoredInputStream armorIn = (ArmoredInputStream) decoder;
                    int ch;
                    while ((ch = armorIn.read()) >= 0 && armorIn.isClearText()) {
                        outputStream.write(ch);
                    }

                    PGPObjectFactory objectFactory = new JcaPGPObjectFactory(armorIn);
                    Object next;
                    while ((next = objectFactory.nextObject()) != null) {
                        if (next instanceof PGPSignatureList) {
                            PGPSignatureList signatureList = (PGPSignatureList) next;
                            return new Signatures() {
                                @Override
                                public void writeTo(OutputStream signatureOutputStream) throws IOException {
                                    OutputStream sigOut = armor ? new ArmoredOutputStream(signatureOutputStream) : signatureOutputStream;
                                    for (PGPSignature signature : signatureList) {
                                        signature.encode(sigOut);
                                    }
                                    sigOut.close();
                                }
                            };
                        }
                    }
                } else {
                    PGPObjectFactory objectFactory = new JcaPGPObjectFactory(decoder);
                    Object next;
                    while ((next = objectFactory.nextObject()) != null) {
                        if (next instanceof PGPLiteralData) {
                            PGPLiteralData literalData = (PGPLiteralData) next;
                            Streams.pipeAll(literalData.getDataStream(), outputStream);
                        }

                        if (next instanceof PGPSignatureList) {
                            PGPSignatureList signatureList = (PGPSignatureList) next;
                            return new Signatures() {
                                @Override
                                public void writeTo(OutputStream signatureOutputStream) throws IOException {
                                    OutputStream sigOut = armor ? new ArmoredOutputStream(signatureOutputStream) : signatureOutputStream;
                                    for (PGPSignature signature : signatureList) {
                                        signature.encode(sigOut);
                                    }
                                    sigOut.close();
                                }
                            };
                        }
                    }
                }
                throw new SOPGPException.BadData("No signatures found.");
            }
        };
    }
}
