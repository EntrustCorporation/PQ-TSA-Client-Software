
package com.entrust.pdftsa.TSAclient.tsa;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.URL;
import java.net.URLConnection;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Collection;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.tsp.MessageImprint;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.util.Store;

import com.entrust.pdftsa.TSAclient.http.HTTPAttestationClient;
import com.entrust.pdftsa.TSAclient.pdf_management.dltsa.DLTimestampRequest;
import com.entrust.pdftsa.TSAclient.pdf_management.dltsa.DLTimestampRequestExtensions;
import com.entrust.pdftsa.TSAclient.signature.EntrustPdfSignature;
import com.entrust.pdftsa.TSAclient.tsa.config.DistributedLedger;
import com.entrust.pdftsa.TSAclient.tsa.config.TsaConfiguration;
import com.itextpdf.commons.utils.Base64;
import com.itextpdf.commons.utils.SystemUtil;
import com.itextpdf.kernel.exceptions.PdfException;
import com.itextpdf.signatures.BouncyCastleDigest;
import com.itextpdf.signatures.DigestAlgorithms;
import com.itextpdf.signatures.ITSAClient;


public class DLTSAClient implements ITSAClient {
    public static final String DEFAULT_HASH_ALGORITHM = "SHA-256";
    protected String digestAlgorithm;
    private TsaConfiguration tsaConfiguration;

    private EntrustPdfSignature pdfSignatures = null;

    public DLTSAClient(TsaConfiguration tsaConfig) {
        this.tsaConfiguration = tsaConfig;
        this.digestAlgorithm = DEFAULT_HASH_ALGORITHM;
    }

    public DLTSAClient(EntrustPdfSignature pdfSignatures, TsaConfiguration tsaConfig) {
        this.pdfSignatures = pdfSignatures;
        this.tsaConfiguration = tsaConfig;
        this.digestAlgorithm = DEFAULT_HASH_ALGORITHM;
    }

    public int getTokenSizeEstimate() {
        return this.tsaConfiguration.tsa.reservedPdfTimeStampSize;
    }

    public String getTSAReqPolicy() {
        return this.tsaConfiguration.tsa.policyID;
    }

    public void setTSAReqPolicy(String tsaReqPolicy) {
        this.tsaConfiguration.tsa.policyID = tsaReqPolicy;
    }

    public MessageDigest getMessageDigest() throws GeneralSecurityException {
        return new BouncyCastleDigest().getMessageDigest(this.digestAlgorithm);
    }

    public byte[] getTimeStampToken(byte[] imprint) throws Exception {
        System.out.println("* Adding Document TimeStamp ");
        if(pdfSignatures != null && pdfSignatures.lastContainsPromise()) {
            TimeStampToken timeStampToken = pdfSignatures.getPromToProofTSToken(imprint);
            return timeStampToken.getEncoded();
        }
        
        byte[] respBytes = null;
        TimeStampRequestGenerator tsqGenerator = new TimeStampRequestGenerator();
        tsqGenerator.setCertReq(true);
        if (tsaConfiguration.tsa.policyID != null && !tsaConfiguration.tsa.policyID.isBlank()) {
            tsqGenerator.setReqPolicy(new ASN1ObjectIdentifier(tsaConfiguration.tsa.policyID));
        }

        BigInteger nonce = BigInteger.valueOf(SystemUtil.getTimeBasedSeed());
        TimeStampRequest request = tsqGenerator.generate(new ASN1ObjectIdentifier(DigestAlgorithms.getAllowedDigest(this.digestAlgorithm)), imprint, nonce);
        byte[] requestBytes = request.getEncoded();
        System.out.println("** Requesting TimeStamp to " + tsaConfiguration.tsa.URL + "...");
        respBytes = this.getTSAResponse(requestBytes);
        TimeStampResponse response = new TimeStampResponse(respBytes);
        response.validate(request);

        PKIFailureInfo failure = response.getFailInfo();
        int value = failure == null ? 0 : failure.intValue();
        if (value != 0) {
            throw (new PdfException("Invalid TSA {0} response code {1}.")).setMessageParams(new Object[]{this.tsaConfiguration.tsa.URL, String.valueOf(value)});
        } 
        TimeStampToken tsToken = response.getTimeStampToken();
        if (tsToken == null) {
            throw (new PdfException("TSA {0} failed to return time stamp token: {1}.")).setMessageParams(new Object[]{this.tsaConfiguration.tsa.URL, response.getStatusString()});
        } 
        
        printTSTTokenInfo(tsToken);

        DLTimestampRequestExtensions extensions = DLTimestampRequestExtensions.createExtensionsWithPromises(tsToken);
        if (extensions == null )
            return tsToken.getEncoded();

        if(tsaConfiguration.distributedLedger == null)
            throw new Exception("TimeStamp Response includes a DL Promise and no Asynchronous policy was specified in configuration");
        
        if( tsaConfiguration.distributedLedger.getAsyncPolicy().equals(DistributedLedger.AsyncPolicy.SKIPWAITPROOF))
            return tsToken.getEncoded();
            
        return waitProof(tsToken,imprint,nonce,extensions);
    }

    public TimeStampToken verifySignature(Attribute attribute, MessageImprint imprint) throws Exception {
        TimeStampRequestGenerator tsqGenerator = new TimeStampRequestGenerator();
        tsqGenerator.setCertReq(true);
        if (tsaConfiguration.tsa.policyID != null && !tsaConfiguration.tsa.policyID.isBlank()) {
            tsqGenerator.setReqPolicy(new ASN1ObjectIdentifier(tsaConfiguration.tsa.policyID));
        }
        BigInteger nonce = BigInteger.valueOf(SystemUtil.getTimeBasedSeed());
        DLTimestampRequestExtensions extensions = DLTimestampRequestExtensions.
                createExtensionsWithPromises(attribute);
        byte[] requestBytes = new DLTimestampRequest(
                imprint,
                new ASN1ObjectIdentifier(tsaConfiguration.tsa.policyID),
                new ASN1Integer(nonce),
                ASN1Boolean.TRUE,
                extensions).getEncoded();
        TimeStampRequest request = tsqGenerator.generate(new ASN1ObjectIdentifier(DigestAlgorithms.getAllowedDigest(this.digestAlgorithm)), imprint.getHashedMessage(), nonce);
        System.out.println("** Requesting TimeStamp to " + tsaConfiguration.tsa.URL + "...");
        byte[] respBytes = this.getTSAResponse(requestBytes);
        TimeStampResponse response = new TimeStampResponse(respBytes);
        response.validate(request);

        PKIFailureInfo failure = response.getFailInfo();
        int value = failure == null ? 0 : failure.intValue();
        if (value != 0) {
            throw (new PdfException("Invalid TSA {0} response code {1}.")).setMessageParams(new Object[]{this.tsaConfiguration.tsa.URL, String.valueOf(value)});
        } else {
            TimeStampToken tsToken = response.getTimeStampToken();
            printTSTTokenInfo(tsToken);
            if (tsToken == null) {
                throw (new PdfException("TSA {0} failed to return time stamp token: {1}.")).setMessageParams(new Object[]{this.tsaConfiguration.tsa.URL, response.getStatusString()});
            }
            else {
                return tsToken;
            }
        }

    }

    protected byte[] getTSAResponse(byte[] requestBytes) throws Exception {
        TsaResponse response = getTsaResponseForUserRequest(this.tsaConfiguration.tsa.URL, requestBytes);
        InputStream inp = response.tsaResponseStream;
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        byte[] buffer = new byte[1024];
        int bytesRead = 0;
        
        while((bytesRead = inp.read(buffer, 0, buffer.length)) >= 0) {
            baos.write(buffer, 0, bytesRead);

            if(baos.size() > getTokenSizeEstimate()){
                throw new Exception("Response size from TSA is too large, configured maximum is " + getTokenSizeEstimate() + " bytes");
            }
        }

        byte[] respBytes = baos.toByteArray();
        if (response.encoding != null && response.encoding.equalsIgnoreCase("base64")) {
            respBytes = Base64.decode(new String(respBytes, StandardCharsets.US_ASCII));
        }

        return respBytes;
    }

    public void setConfiguration(TsaConfiguration configuration){
        this.tsaConfiguration = configuration;
    }


    private byte[] treatDLTSAgetTimeStampToken(TimeStampToken oldtsToken, byte[] imprint, BigInteger nonce, DLTimestampRequestExtensions extensions) throws Exception {
        byte[] requestBytes = new DLTimestampRequest(
                new MessageImprint(oldtsToken.getTimeStampInfo().getHashAlgorithm(), imprint),
                new ASN1ObjectIdentifier(tsaConfiguration.tsa.policyID),
                new ASN1Integer(nonce),
                ASN1Boolean.TRUE,
                extensions).getEncoded();
        TimeStampRequestGenerator tsqGenerator = new TimeStampRequestGenerator();
        TimeStampRequest requestDL = tsqGenerator.generate(new ASN1ObjectIdentifier(DigestAlgorithms.getAllowedDigest(this.digestAlgorithm)), imprint, nonce); //aqui
        byte[] respBytes = null;
        respBytes = this.getTSAResponse(requestBytes);


        TimeStampResponse responseDL = new TimeStampResponse(respBytes);
        responseDL.validate(requestDL);
        int status = responseDL.getStatus();
                                /*
                SUPPORTED
                3 -> WAITING
                0 -> GRANTED (SUCCESS)
                2 -> REJECTION
                -----------------------------------
                UNSUPPORTED
                1 -> GRANTED WITH MODS
                 */
        switch (status){
            case 0:
                TimeStampToken tsToken = responseDL.getTimeStampToken();
                printTSTTokenInfo(tsToken);
                return tsToken.getEncoded();

            case 1:
                return new byte[] {1};

            case 2:
                return  new byte[] {2};

            case 3:
                return  new byte[] {3};
            default:
                throw new Exception("Unknown STATUS: " +status);
        }

    }

    private void printTSTTokenInfo(TimeStampToken tsToken) throws Exception {
        System.out.println("**** TSA Name: " + tsToken.getTimeStampInfo().getTsa().toString());
        System.out.println("**** Hash Algorithm: "+ tsToken.getTimeStampInfo().getHashAlgorithm().getAlgorithm().toString());
        System.out.println("**** Generation Time: " + tsToken.getTimeStampInfo().getGenTime().toString());
        Store responseCertificatesStore = tsToken.toCMSSignedData().getCertificates();
        Collection<X509CertificateHolder> certs = responseCertificatesStore.getMatches(null);
        X509CertificateHolder lastCertificate = null;
        for (X509CertificateHolder certificate : certs) {
            lastCertificate = certificate;
        }
        if (lastCertificate == null)
            throw new Exception("Could not get last certificate info from tsaToken");
        
        AlgorithmIdentifier sigalg = lastCertificate.getSignatureAlgorithm();
        System.out.println("**** Signature Algorithm: " + sigalg.getAlgorithm().toString());
    }

    private byte[] waitProof(TimeStampToken tsToken, byte[] imprint, BigInteger nonce, DLTimestampRequestExtensions extensions) throws Exception {
        long startTime = System.currentTimeMillis();
        int attempts = 0;
        while (true){
            System.out.println("Attempt "+attempts);
            byte [] result = treatDLTSAgetTimeStampToken(tsToken,imprint,nonce,extensions);
            if (result.length == 0){
                throw new Exception("TSA returned empty or not parseable token");
            } else if (result.length == 1 && result[0] == 1) {// GRANTED WITH MODS WITH MODS
                throw new Exception("TSA returned token with status: GRANTED WITH MODS and it is not supported by the client");
            } else if (result.length == 1 && result[0] == 2) { //REJECTED
                throw new Exception("TSA returned token with status: REJECTED");
            } else if (result.length == 1 && result [0] == 3 ) { //WAITING
                // Check elapsed time
                if (System.currentTimeMillis() - startTime > tsaConfiguration.distributedLedger.maxWaitTime) {
                    throw new TimeoutException("TSA confirmation exceeded the specified time limit " + tsaConfiguration.distributedLedger.maxWaitTime + " ms");
                }
            } else { // token status is 10(GRANTED)
                System.out.println("TSA returned (GRANTED)");
                System.out.println("\n");
                System.out.println("* Validating attestation");
                String attestation = DLTimestampRequestExtensions.getDLAttestation(tsToken);
                HTTPAttestationClient httpAttestationClient = new HTTPAttestationClient();
                httpAttestationClient.getDLAttestationURL(tsaConfiguration.distributedLedger.proofsUrl, attestation);
                return result;
            }
            System.out.println("Status received is : "+result[0]);
            TimeUnit.SECONDS.sleep(tsaConfiguration.distributedLedger.threshold);
            attempts ++;
        }
    }

    private static class TsaResponse {
        public String encoding;
        public InputStream tsaResponseStream;
    }

    private TsaResponse getTsaResponseForUserRequest(String tsaUrl, byte[] requestBytes) throws Exception {
        URL url = new URL(tsaUrl);
        URLConnection tsaConnection = url.openConnection();
        tsaConnection.setDoInput(true);
        tsaConnection.setDoOutput(true);
        tsaConnection.setUseCaches(false);
        tsaConnection.setRequestProperty("Content-Type", "application/timestamp-query");
        tsaConnection.setRequestProperty("Content-Transfer-Encoding", "binary");

        OutputStream out = tsaConnection.getOutputStream();
        out.write(requestBytes);
        out.close();

        TsaResponse response = new TsaResponse();
        response.tsaResponseStream = tsaConnection.getInputStream();
        response.encoding = tsaConnection.getContentEncoding();
        return response;
    }


}







