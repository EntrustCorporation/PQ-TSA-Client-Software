package com.entrust.pdftsa.TSAclient.tsa.config;

public class TSA {
    public String URL;
    public String tlsRootCertificate;
    public String policyID;
    public int reservedPdfTimeStampSize;

    public TSA() {}
    public TSA(String URL, String tlsRootCertificate, String policyID, int reservedPdfTimeStampSize) {
        this.URL = URL;
        this.tlsRootCertificate = tlsRootCertificate;
        this.policyID = policyID;
        this.reservedPdfTimeStampSize = reservedPdfTimeStampSize;
    }
}
