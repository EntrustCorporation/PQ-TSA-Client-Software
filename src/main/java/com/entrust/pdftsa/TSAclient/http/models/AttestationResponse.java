package com.entrust.pdftsa.TSAclient.http.models;

import org.json.JSONObject;

public class AttestationResponse {

    private String id = null;
    private String status = null;
    private Promise promise = null;
    private Proof proof = null;
    private String self = null;

    public AttestationResponse(String id, String status, Promise promise, Proof proof, String self) {
        this.id = id;
        this.status = status;
        this.promise = promise;
        this.proof = proof;
        this.self = self;
    }

    public AttestationResponse(JSONObject jsonObject) {
        this.id = jsonObject.getString("id");
        this.status = jsonObject.getString("status");
        this.promise = new Promise(jsonObject.getJSONObject("promise"));
        this.proof = new Proof(jsonObject.getJSONObject("proof"));
        this.self = jsonObject.getString("self");
    }

    public String getId() {
        return id;
    }

    public String getStatus() {
        return status;
    }

    public Promise getPromise() {
        return promise;
    }

    public Proof getProof() {
        return proof;
    }

    public String getSelf() {
        return self;
    }
}


