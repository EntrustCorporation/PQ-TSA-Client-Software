package com.entrust.pdftsa.TSAclient.signature;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.tsp.TimeStampToken;

import com.itextpdf.kernel.exceptions.PdfException;
import com.itextpdf.kernel.pdf.PdfDeveloperExtension;
import com.itextpdf.kernel.pdf.PdfDictionary;
import com.itextpdf.kernel.pdf.PdfName;
import com.itextpdf.kernel.pdf.PdfReader;
import com.itextpdf.kernel.pdf.PdfString;
import com.itextpdf.kernel.pdf.PdfVersion;
import com.itextpdf.kernel.pdf.StampingProperties;
import com.itextpdf.signatures.ITSAClient;
import com.itextpdf.signatures.PdfSignature;
import com.itextpdf.signatures.PdfSigner;
import com.itextpdf.signatures.exceptions.SignExceptionMessageConstant;

public class EntrustPdfSigner extends PdfSigner {

    public EntrustPdfSigner(PdfReader reader, OutputStream outputStream, StampingProperties properties)
            throws IOException {
        super(reader, outputStream, properties);
    }

    public InputStream getRange(int contentEstimated) throws IOException {
        PdfSignature dic = new PdfSignature(PdfName.Adobe_PPKLite, PdfName.ETSI_RFC3161);
        dic.put(PdfName.Type, PdfName.DocTimeStamp);
        super.cryptoDictionary = dic;
        Map<PdfName, Integer> exc = new HashMap<>();
        exc.put(PdfName.Contents, contentEstimated * 2 + 2);
        super.preClose(exc);
        return super.getRangeStream();
    }

    public void timestamp(String signatureName, TimeStampToken timeStampToken, InputStream data) throws Exception {
        PdfDictionary dic2 = new PdfDictionary();
        if ((this.document.getPdfVersion().compareTo(PdfVersion.PDF_2_0) < 0)) {
            addDeveloperExtension(PdfDeveloperExtension.ESIC_1_7_EXTENSIONLEVEL5);
        }

        byte[] tsToken = timeStampToken.getEncoded();
        if (closed) {
            throw new PdfException(SignExceptionMessageConstant.THIS_INSTANCE_OF_PDF_SIGNER_ALREADY_CLOSED);
        }

        int contentEstimated = tsToken.length + 32;
        setFieldName(signatureName + "_PROOF");
        PdfSignature dic = new PdfSignature(PdfName.Adobe_PPKLite, PdfName.ETSI_RFC3161);
        dic.put(PdfName.Type, PdfName.DocTimeStamp);
        cryptoDictionary = dic;
        Map<PdfName, Integer> exc = new HashMap<>();
        exc.put(PdfName.Contents, contentEstimated * 2 + 2);
        preClose(exc);
        if (contentEstimated + 2 < tsToken.length)
            throw new IOException("Not enough space");

        byte[] paddedSig = new byte[contentEstimated];
        System.arraycopy(tsToken, 0, paddedSig, 0, tsToken.length);
        dic2.put(PdfName.Contents, new PdfString(paddedSig).setHexWriting(true));

        close(dic2);
        closed = true;
    }

    public byte[] calculateNewTsImprint(ITSAClient tsaClient) throws IOException, GeneralSecurityException {
        Map<PdfName, Integer> exc = new HashMap<>();
        int contentEstimated = tsaClient.getTokenSizeEstimate();
        exc.put(PdfName.Contents, contentEstimated * 2 + 2);

        PdfSignature dic = new PdfSignature(PdfName.Adobe_PPKLite, PdfName.ETSI_RFC3161);
        dic.put(PdfName.Type, PdfName.DocTimeStamp);
        cryptoDictionary = dic;

        super.preClose(exc);
        InputStream data = super.getRangeStream();
        MessageDigest messageDigest = tsaClient.getMessageDigest();
        byte[] buf = new byte[4096];
        int n;
        while ((n = data.read(buf)) > 0) {
            messageDigest.update(buf, 0, n);
        }
        return messageDigest.digest();
    }

}
