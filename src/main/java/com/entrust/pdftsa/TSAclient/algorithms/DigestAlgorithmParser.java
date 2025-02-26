package com.entrust.pdftsa.TSAclient.algorithms;
import java.security.NoSuchAlgorithmException;

public class DigestAlgorithmParser {

    public static String parseAlgorithmToOID(String algorithmName) throws NoSuchAlgorithmException {
        algorithmName = algorithmName.toUpperCase();
        switch (algorithmName) {
            case "MD2":
                return "1.2.840.113549.2.2";
            case "MD5":
                return "1.2.840.113549.2.5";
            case "SHA1":
            case "SHA-1":
                return "1.3.14.3.2.26";
            case "SHA256":
            case "SHA-256":
                return "2.16.840.1.101.3.4.2.1";
            case "SHA384":
            case "SHA-384":
                return "2.16.840.1.101.3.4.2.2";
            case "SHA512":
            case "SHA-512":
                return "2.16.840.1.101.3.4.2.3";
            default:
                throw new NoSuchAlgorithmException("Unsupported algorithm: " + algorithmName);
        }
    }
}
