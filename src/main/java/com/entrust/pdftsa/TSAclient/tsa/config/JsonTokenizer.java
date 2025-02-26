package com.entrust.pdftsa.TSAclient.tsa.config;

public class JsonTokenizer {
    public enum JsonToken {
        START_OBJECT,
        END_OBJECT,
        COLON,
        COMMA,
        STRING,
        UNKNOWN
    }

    private final String json;
    private int position;

    public JsonTokenizer(String json) {
        this.json = json;
        this.position = 0;
    }

    public JsonToken peek() {
        skipWhitespace();
        if (position == json.length()) {
            return null;
        }

        char currentChar = json.charAt(position);
        switch (currentChar) {
            case '{':
                return JsonToken.START_OBJECT;
            case '}':
                return JsonToken.END_OBJECT;
            case ':':
                return JsonToken.COLON;
            case ',':
                return JsonToken.COMMA;
            case '"':
                return JsonToken.STRING;
            default:
                return JsonToken.UNKNOWN;
        }
    }

    public String consumeToken(JsonToken expectedToken) {
        skipWhitespace();

        if (expectedToken == JsonToken.STRING) {
            if (json.charAt(position) != '"') {
                throw new IllegalStateException("Expected a string token");
            }
            int start = position + 1;
            position = json.indexOf('"', start);
            if (position == -1) {
                throw new IllegalStateException("Unclosed string token");
            }
            String value = json.substring(start, position);
            position++;
            return value;
        }

        char expectedChar = json.charAt(position++);
        switch (expectedToken) {
            case START_OBJECT:
                if (expectedChar != '{') {
                    throw new IllegalStateException("Expected '{'");
                }
                break;
            case END_OBJECT:
                if (expectedChar != '}') {
                    throw new IllegalStateException("Expected '}'");
                }
                break;
            case COLON:
                if (expectedChar != ':') {
                    throw new IllegalStateException("Expected ':'");
                }
                break;
            case COMMA:
                if (expectedChar != ',') {
                    throw new IllegalStateException("Expected ','");
                }
                break;
            default:
                throw new IllegalStateException("Unexpected token type: " + expectedToken);
        }

        return null;
    }

    private void skipWhitespace() {
        while (position < json.length() && Character.isWhitespace(json.charAt(position))) {
            position++;
        }
    }
}
