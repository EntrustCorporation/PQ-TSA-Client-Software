package com.entrust.pdftsa.TSAclient.tsa.config;

public class TsaConfiguration {
    public com.entrust.pdftsa.TSAclient.tsa.config.TSA tsa;
    public com.entrust.pdftsa.TSAclient.tsa.config.DistributedLedger distributedLedger;

    @Override
    public String toString() {
        return "Configuration{" +
                "tsa=" + tsa +
                ", distributedLedger=" + distributedLedger +
                '}';
    }

}



