package com.entrust.pdftsa.TSAclient.tsa.config;

import java.io.IOException;
import java.nio.file.Path;

public class JsonParser {
    public static TsaConfiguration parseJson(String jsonPath) throws IOException {
        String jsonContent = new String(java.nio.file.Files.readAllBytes(Path.of(jsonPath)));
        JsonTokenizer tokenizer = new JsonTokenizer(jsonContent);
        JsonParserHelper parser = new JsonParserHelper(tokenizer);
        return parser.parseConfiguration();
    }
}
