package com.entrust.pdftsa.TSAclient.signature;

import java.security.MessageDigest;
import java.security.Provider;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.List;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.tsp.MessageImprint;
import org.bouncycastle.asn1.tsp.TSTInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.tsp.TimeStampToken;

import com.entrust.pdftsa.TSAclient.http.HTTPAttestationClient;
import com.entrust.pdftsa.TSAclient.pdf_management.dltsa.DLTimestampRequestExtensions;
import com.entrust.pdftsa.TSAclient.tsa.DLTSAClient;
import com.entrust.pdftsa.TSAclient.tsa.config.TsaConfiguration;
import com.itextpdf.bouncycastle.asn1.tsp.TSTInfoBC;
import com.itextpdf.kernel.pdf.PdfDocument;
import com.itextpdf.kernel.pdf.PdfReader;
import com.itextpdf.signatures.PdfPKCS7;
import com.itextpdf.signatures.SignatureUtil;

public class EntrustPdfSignature {
    public static final String PROMISE_OID = "2.5.29.69";
    private static final String PROOF_OID = "2.5.29.72";

    private PdfDocument pdfDocument;
    private TsaConfiguration config;

    public EntrustPdfSignature(PdfReader reader, TsaConfiguration configuration) {
        pdfDocument = new PdfDocument(reader);
        config = configuration;
    }

    public void checkSignaturesInfo() throws Exception {
        List<String> signatureNames = extractSignatureNames();
        if (signatureNames.isEmpty()) {
            System.out.println("No signatures found in the PDF.");
            return;
        }

        System.out.println("** " + signatureNames.size() + " signature(s) found\n");
        int counter = 1;
        for(String signatureName : signatureNames) {
            com.itextpdf.signatures.PdfSignature lastSignature = extractSignatureDetails(signatureName);
            System.out.println("-----------------------------------------");
            System.out.println("Signature " + counter++ + " Details : ");
            printCertificateInfo(signatureName);
            if(lastSignature.getName() != null)
                System.out.println("* PDF Signature Name: " + lastSignature.getName());

            if(lastSignature.getLocation() != null)
                System.out.println("* PDF Signature Location: " + lastSignature.getLocation());
            
            if(lastSignature.getReason() != null)
                System.out.println("* PDF Signature Reason: " + lastSignature.getReason());
            
            if(lastSignature.getDate() != null)
                System.out.println("* PDF Signature Date: " + lastSignature.getDate());
            System.out.println("-----------------------------------------");
            System.out.println("");
        }
    }

    public boolean lastContainsPromise() throws Exception {
        List<String> signatureNames = extractSignatureNames();
        if (signatureNames.isEmpty()) {
            System.out.println("No signatures found in the PDF.");
            return false;
        }

        com.itextpdf.signatures.PdfSignature lastSignature = extractSignatureDetails(
                signatureNames.get(signatureNames.size() - 1));

        Attribute attribute = extractPromiseFromSignature(lastSignature);
        return attribute != null && attribute.getAttrType().equals(new ASN1ObjectIdentifier(PROMISE_OID));
    }

    public boolean lastContainsProof() throws Exception {
        List<String> signatureNames = extractSignatureNames();
        if (signatureNames.isEmpty()) {
            System.out.println("No signatures found in the PDF.");
            return false;
        }

        SignatureUtil signatureUtil = new SignatureUtil(pdfDocument);
        PdfPKCS7 pdfPKCS7= signatureUtil.readSignatureData(signatureNames.get(signatureNames.size() - 1));
        TSTInfoBC tstInfo = (TSTInfoBC) pdfPKCS7.getTimeStampTokenInfo();
        
        
        if(tstInfo == null)
            return false;

        Extensions tstInfoExtensions = tstInfo.getTstInfo().getExtensions();
        if(tstInfoExtensions == null)
            return false;

        return tstInfoExtensions.getExtension(new ASN1ObjectIdentifier(EntrustPdfSignature.PROOF_OID)) != null;
    }

    public int getNumberSignatures() throws Exception {
        List<String> signatureNames = extractSignatureNames();
        return signatureNames.size();
    }

    public TimeStampToken getPromToProofTSToken(byte[] calculatedTsImprint) throws Exception {
        List<String> signatureNames = extractSignatureNames();
        if (signatureNames.isEmpty()) {
            System.out.println("No signatures found in the PDF.");
            return null;
        }

        TimeStampToken lastSignTsToken;
        com.itextpdf.signatures.PdfSignature lastSignature = extractSignatureDetails(
                    signatureNames.get(signatureNames.size() - 1));

        SignatureUtil signatureUtil = new SignatureUtil(pdfDocument);

        Attribute attribute = extractPromiseFromSignature(lastSignature);
        if (attribute == null) {
            PdfPKCS7 pdfPKCS7= signatureUtil.readSignatureData(signatureNames.get(signatureNames.size() - 1));
            TSTInfo itstInfo = (TSTInfo)pdfPKCS7.getTimeStampTokenInfo();
            if(itstInfo != null && itstInfo.getExtensions().getExtension(new ASN1ObjectIdentifier(PROOF_OID)) != null) {
                    System.out.println("* Last Document TimeStamp includes a DL TSA Proof");
                }
            
            return null;
        }
        
        if (attribute != null){
            DLTSAClient client = new DLTSAClient(config);
            MessageDigest messageDigest = client.getMessageDigest();
            MessageImprint messageImprint = new MessageImprint(new AlgorithmIdentifier(new ASN1ObjectIdentifier(com.entrust.pdftsa.TSAclient.algorithms.DigestAlgorithmParser.parseAlgorithmToOID( messageDigest.getAlgorithm()))),calculatedTsImprint);
            lastSignTsToken = client.verifySignature(attribute,messageImprint);
            Extension extension = lastSignTsToken.getTimeStampInfo().getExtensions().getExtension(new ASN1ObjectIdentifier("2.5.29.72"));
            if (extension != null){
                System.out.println("* Signature promise validated");
                System.out.println("* Validating attestation");
                String attestation = DLTimestampRequestExtensions.getDLAttestation(attribute);
                HTTPAttestationClient httpAttestationClient = new HTTPAttestationClient();
                httpAttestationClient.getDLAttestationURL(config.distributedLedger.proofsUrl, attestation);
                return lastSignTsToken;
            }
            System.out.println("* Signature promise could no be validated");
        }
        
        // Will never be reached
        return null;
    }


    private void printCertificateInfo(String signatureName) throws Exception {
        SignatureUtil signUtil = new SignatureUtil(pdfDocument);

        PdfPKCS7 pkcs7 = null;
        try {
            pkcs7 = signUtil.readSignatureData(signatureName);
        }catch (Exception e){
            Provider p = new BouncyCastlePQCProvider();
            Security.addProvider(p);
            pkcs7 = signUtil.readSignatureData(signatureName, p.getName());
        }
        if (pkcs7 == null){
            throw new Exception("Could not extract PKCS7 signature object");
        }
        if(pkcs7.isTsp()) {
            System.out.println("* Signature is a LTV Document TimeStamp: " + pkcs7.getTimeStampTokenInfo().getGenTime());
        }
        System.out.println("* Signature Integrity: " + pkcs7.verifySignatureIntegrityAndAuthenticity() );
        X509Certificate certificate = pkcs7.getSigningCertificate();
        System.out.println("* Signer Subject: " + certificate.getSubjectX500Principal().toString() );
        System.out.println("* Signer Issuer: " + certificate.getIssuerX500Principal().toString() );
        System.out.println("* Signer Serial Number: " + certificate.getSerialNumber() );
        System.out.println("* Signer Signature Algorithm: " + certificate.getSigAlgName() );
        if (!pkcs7.isTsp() && pkcs7.getTimeStampTokenInfo() != null) {
            System.out.println("* Signature includes a TimeStamp: " + pkcs7.getTimeStampTokenInfo().getGenTime());
        }


    }

    private List<String> extractSignatureNames() {
        SignatureUtil signatureUtil = new SignatureUtil(pdfDocument);
        return signatureUtil.getSignatureNames();
    }

    private com.itextpdf.signatures.PdfSignature extractSignatureDetails(String signatureName) {
        SignatureUtil signatureUtil = new SignatureUtil(pdfDocument);
        return signatureUtil.getSignature(signatureName);
    }

    private Attribute extractPromiseFromSignature(com.itextpdf.signatures.PdfSignature signature) throws CMSException {
            // Get the timestamp token info
        byte[] signatureContents = signature.getContents().getValueBytes();
        CMSSignedData cmsSignedData = new CMSSignedData(signatureContents);
        SignerInformation signerInfo = cmsSignedData.getSignerInfos().getSigners().iterator().next();
        AttributeTable attributeTable = signerInfo.getUnsignedAttributes();
        if (attributeTable == null)return  null;
        return attributeTable.get(new ASN1ObjectIdentifier(EntrustPdfSignature.PROMISE_OID));


    }
}
