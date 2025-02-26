package com.entrust.pdftsa.TSAclient.http.models;

import org.json.JSONObject;

public class Promise {

    private String contentType = null;
    private String data = null;


    public Promise(String contentType, String data) {
        this.contentType = contentType;
        this.data = data;
    }

    public Promise(JSONObject jsonObject) {
        this.contentType = jsonObject.getString("contentType");
        this.data = jsonObject.getString("data");
    }

    public String getContentType() {
        return contentType;
    }

    public String getData() {
        return data;
    }

}
