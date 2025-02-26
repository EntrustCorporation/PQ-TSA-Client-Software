package com.entrust.pdftsa.TSAclient.pdf_management.dltsa;


import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.tsp.MessageImprint;
import org.bouncycastle.asn1.tsp.TimeStampReq;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.tsp.TimeStampToken;

import com.entrust.pdftsa.TSAclient.pdf_management.pdf.PDFFile;


public class DLTimestampRequest extends TimeStampReq {

    public DLTimestampRequest(MessageImprint messageImprint,
                                             ASN1ObjectIdentifier tsaPolicy,
                                             ASN1Integer nonce,
                                             ASN1Boolean certReq,
                                             Extensions extensions) {
        super(messageImprint, tsaPolicy, nonce, certReq, extensions);
    }

    public static DLTimestampRequest createTimestampRequest(String pdfFilePath)
            throws Exception {
        TimeStampToken timestampToken = PDFFile.getLastTimestampToken(pdfFilePath);
        MessageImprint messageImprint = PDFFile.getTimestampedPDFMessageImprint(pdfFilePath, timestampToken);
        DLTimestampRequestExtensions extensions = DLTimestampRequestExtensions.
                createExtensionsWithPromises(timestampToken);
        return new DLTimestampRequest(
                messageImprint,
                null,
                null,
                ASN1Boolean.TRUE,
                extensions);
    }
}
