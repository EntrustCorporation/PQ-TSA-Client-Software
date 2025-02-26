package com.entrust.pdftsa.TSAclient.tsa.config;


public class JsonParserHelper {

    private JsonTokenizer tokenizer;

    public JsonParserHelper(JsonTokenizer tokenizer) {
        this.tokenizer = tokenizer;
    }

    public TsaConfiguration parseConfiguration() {
        TsaConfiguration configuration = new TsaConfiguration();
        tokenizer.consumeToken(JsonTokenizer.JsonToken.START_OBJECT);

        while (tokenizer.peek() != JsonTokenizer.JsonToken.END_OBJECT) {
            String fieldName = tokenizer.consumeToken(JsonTokenizer.JsonToken.STRING);
            tokenizer.consumeToken(JsonTokenizer.JsonToken.COLON);

            if ("tsa".equals(fieldName)) {
                configuration.tsa = parseTSA();
            } else if ("distributedLedger".equals(fieldName)) {
                configuration.distributedLedger = parseDistributedLedger();
            } else {
                throw new IllegalStateException("Unexpected field: " + fieldName);
            }

            if (tokenizer.peek() == JsonTokenizer.JsonToken.COMMA) {
                tokenizer.consumeToken(JsonTokenizer.JsonToken.COMMA);
            }
        }

        tokenizer.consumeToken(JsonTokenizer.JsonToken.END_OBJECT);
        return configuration;
    }

    private TSA parseTSA() {
        TSA tsa = new TSA();
        tokenizer.consumeToken(JsonTokenizer.JsonToken.START_OBJECT);

        while (tokenizer.peek() != JsonTokenizer.JsonToken.END_OBJECT) {
            String fieldName = tokenizer.consumeToken(JsonTokenizer.JsonToken.STRING);
            tokenizer.consumeToken(JsonTokenizer.JsonToken.COLON);

            switch (fieldName) {
                case "url":
                    tsa.URL = tokenizer.consumeToken(JsonTokenizer.JsonToken.STRING);
                    break;
                case "tlsRootCertificate":
                    tsa.tlsRootCertificate = tokenizer.consumeToken(JsonTokenizer.JsonToken.STRING);
                    break;
                case "policyId":
                    tsa.policyID = tokenizer.consumeToken(JsonTokenizer.JsonToken.STRING);
                    break;
                case "reservedPdfTimeStampSize":
                    tsa.reservedPdfTimeStampSize = Integer.parseInt(tokenizer.consumeToken(JsonTokenizer.JsonToken.STRING));
                    break;
                default:
                    throw new IllegalStateException("Unexpected field: " + fieldName);
            }

            if (tokenizer.peek() == JsonTokenizer.JsonToken.COMMA) {
                tokenizer.consumeToken(JsonTokenizer.JsonToken.COMMA);
            }
        }

        tokenizer.consumeToken(JsonTokenizer.JsonToken.END_OBJECT);
        return tsa;
    }

    private DistributedLedger parseDistributedLedger() {
        DistributedLedger distributedLedger = new DistributedLedger();
        tokenizer.consumeToken(JsonTokenizer.JsonToken.START_OBJECT);

        while (tokenizer.peek() != JsonTokenizer.JsonToken.END_OBJECT) {
            String fieldName = tokenizer.consumeToken(JsonTokenizer.JsonToken.STRING);
            tokenizer.consumeToken(JsonTokenizer.JsonToken.COLON);

            switch (fieldName) {
                case "proofsUrl":
                    distributedLedger.proofsUrl = String.valueOf(tokenizer.consumeToken(JsonTokenizer.JsonToken.STRING));
                    break;
                case "asyncPolicy":
                    distributedLedger.asyncPolicy = DistributedLedger.AsyncPolicy.valueOf(tokenizer.consumeToken(JsonTokenizer.JsonToken.STRING));
                    break;
                case "maxWaitTime":
                    distributedLedger.maxWaitTime = Integer.parseInt(tokenizer.consumeToken(JsonTokenizer.JsonToken.STRING));
                    break;
                case "threshold":
                    distributedLedger.threshold = Integer.parseInt(tokenizer.consumeToken(JsonTokenizer.JsonToken.STRING));
                    break;
                default:
                    throw new IllegalStateException("Unexpected field: " + fieldName);
            }

            if (tokenizer.peek() == JsonTokenizer.JsonToken.COMMA) {
                tokenizer.consumeToken(JsonTokenizer.JsonToken.COMMA);
            }
        }

        tokenizer.consumeToken(JsonTokenizer.JsonToken.END_OBJECT);
        return distributedLedger;
    }
}
