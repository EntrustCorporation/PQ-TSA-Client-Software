
package com.entrust.pdftsa.TSAclient.pdf_management.pdf;

import java.util.List;

import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.tsp.TimeStampToken;

import com.itextpdf.commons.bouncycastle.asn1.tsp.ITSTInfo;
import com.itextpdf.kernel.pdf.PdfDocument;
import com.itextpdf.kernel.pdf.PdfReader;
import com.itextpdf.signatures.PdfPKCS7;
import com.itextpdf.signatures.SignatureUtil;

public class PDFContent extends PdfDocument {
    public PDFContent(PdfReader reader) {
        super(reader);
    }

    private TimeStampToken getTimestampToken(SignatureUtil signUtil, String name) {
        PdfPKCS7 signatureData = signUtil.readSignatureData(name);
        try {
            ITSTInfo itstInfo = signatureData.getTimeStampTokenInfo();
            return new TimeStampToken((ContentInfo) itstInfo);
        }
        catch (Exception e) {
            return null;
        }
    }

    public TimeStampToken getLastTimestampToken() {
        SignatureUtil signUtil = new SignatureUtil(this);
        List<String> names = signUtil.getSignatureNames();
        TimeStampToken timestampToken = null;
        for (String name: names) {
            TimeStampToken lastTimestampToken = this.getTimestampToken(signUtil, name);
            if (lastTimestampToken != null) {
                timestampToken = lastTimestampToken;
            }
        }
        return timestampToken;
    }
}
