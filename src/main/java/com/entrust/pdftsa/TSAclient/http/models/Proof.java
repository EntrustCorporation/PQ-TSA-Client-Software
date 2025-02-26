package com.entrust.pdftsa.TSAclient.http.models;

import org.json.JSONObject;

public class Proof {

    private String contentType = null;
    private String data = null;
    private String distributedLedger = null;
    private String attestation = null;


    public Proof(String contentType, String data, String distributedLedger, String attestation) {
        this.contentType = contentType;
        this.data = data;
        this.distributedLedger = distributedLedger;
        this.attestation = attestation;
    }

    public Proof(JSONObject jsonObject){
        this.contentType = jsonObject.getString("contentType");
        this.data = jsonObject.getString("data");
        this.distributedLedger = jsonObject.getString("distributedLedger");
        this.attestation = jsonObject.getString("attestation");
    }

    public String getContentType() {
        return contentType;
    }

    public String getData() {
        return data;
    }

    public String getDistributedLedger() {
        return distributedLedger;
    }

    public String getAttestation() {
        return attestation;
    }

}
