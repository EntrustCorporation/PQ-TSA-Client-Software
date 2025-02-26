package com.entrust.pdftsa.TSAclient.pdf_management.pdf;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.bouncycastle.asn1.tsp.MessageImprint;
import org.bouncycastle.tsp.TimeStampToken;

import com.itextpdf.kernel.pdf.PdfReader;

public class PDFFile {
    public static TimeStampToken getLastTimestampToken(String path) throws IOException {
        PDFContent pdfContent = new PDFContent(new PdfReader(path));
        TimeStampToken timestampToken = pdfContent.getLastTimestampToken();
        pdfContent.close();

        return timestampToken;
    }

    public static MessageImprint getTimestampedPDFMessageImprint(
            String pdfFilePath,
            TimeStampToken timeStampToken) throws NoSuchAlgorithmException, IOException {
        byte[] fileData = Files.readAllBytes(Paths.get(pdfFilePath));
        byte[] hash = MessageDigest.getInstance("SHA-256").digest(fileData);
        return new MessageImprint(timeStampToken.getTimeStampInfo().getHashAlgorithm(), hash);
    }
}
