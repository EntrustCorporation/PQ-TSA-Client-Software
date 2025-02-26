package com.entrust.pdftsa.TSAclient.tsa.config;

public class DistributedLedger {
    public enum AsyncPolicy {
        WAITPROOF,
        SKIPWAITPROOF
    }

    public AsyncPolicy asyncPolicy;
    public int maxWaitTime;
    public int threshold;
    public String proofsUrl;

    public DistributedLedger() {}
    public DistributedLedger(String proofsUrl, AsyncPolicy asyncPolicy, int maxWaitTime, int threshold) {
        this.proofsUrl = proofsUrl;
        this.asyncPolicy = asyncPolicy;
        this.maxWaitTime = maxWaitTime;
        this.threshold = threshold;
    }

    public AsyncPolicy getAsyncPolicy() {
        return asyncPolicy;
    }

    public int getMaxWaitTime() {
        return maxWaitTime;
    }

    public int getThreshold() {
        return threshold;
    }
}
