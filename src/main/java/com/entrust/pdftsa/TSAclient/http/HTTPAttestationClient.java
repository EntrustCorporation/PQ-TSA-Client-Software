package com.entrust.pdftsa.TSAclient.http;

import org.json.JSONObject;

import com.entrust.pdftsa.TSAclient.http.models.AttestationResponse;

import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

public class HTTPAttestationClient {

    public void getDLAttestationURL(String proofsUrl, String encodedAttestation) throws Exception {
        OkHttpClient client = new OkHttpClient().newBuilder()
                .build();
        System.out.println("* DL Proof URL: " + proofsUrl + "/" + encodedAttestation);
        Request request = new Request.Builder()
                .url(proofsUrl + "/" + encodedAttestation)
                .method("GET", null)
                .build();
        Response response = client.newCall(request).execute();
        AttestationResponse dlAttestationResponse = new AttestationResponse(new JSONObject(response.body().string()));
        System.out.println("** Distributed Ledger used: "+dlAttestationResponse.getProof().getDistributedLedger());
        System.out.println("* Requesting proof attestation info to DL " +
                "\n** Information received from DL: {" + dlAttestationResponse.getProof().getAttestation() + "}");
    }
}
