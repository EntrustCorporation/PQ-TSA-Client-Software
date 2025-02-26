package com.entrust.pdftsa.TSAclient;

import static java.lang.System.exit;

import java.io.FileOutputStream;

import com.entrust.pdftsa.TSAclient.signature.EntrustPdfSignature;
import com.entrust.pdftsa.TSAclient.tsa.DLTSAClient;
import com.entrust.pdftsa.TSAclient.tsa.config.JsonParser;
import com.entrust.pdftsa.TSAclient.tsa.config.TsaConfiguration;
import com.itextpdf.kernel.pdf.PdfReader;
import com.itextpdf.kernel.pdf.StampingProperties;
import com.itextpdf.signatures.PdfSigner;

public class Main {

    private static class CmdArgs {
        public String sourceFile = null;
        public String destinationFile = null;
        public TsaConfiguration config = null;
    }

    public static CmdArgs parseArgs(String[] args) throws Exception {
        CmdArgs parsedArgs = new CmdArgs();
        if (args.length != 3 && args.length != 1) {
            usage();
            exit(1);
        }

        parsedArgs.sourceFile = args[0];
        if(args.length > 1) {
            if (args[0].equals(args[1])){
                throw new Exception("Source file and destination file can not be the same");
            }
            parsedArgs.destinationFile = args[1];
            parsedArgs.config = JsonParser.parseJson(args[2]);
        }
        return parsedArgs;
    }

    public static void usage(){
        System.out.println("\n" +
                "Usage: pdfstamper.sh <Input_PDF_Document> <Output_PDF_Document> <JSON_Configuration_File>\n" +
                "** Verify the signatures of <Input_PDF_Document> and includes a new Document TimeStamp using <JSON_Configuration_File>. Output is written in <Output_PDF_Document>\n" +
                "Usage: pdfstamper.sh <Input_PDF_Document> \n" +
                "** Verify the signatures of <Input_PDF_Document> \n" +
                "\n" +
                "Example 1: pdfstamper.sh my_signed_document.pdf my_signed_document_tsa.pdf config.json\n" +
                "Example 2: pdfstamper.sh my_signed_document.pdf\n" +
                "*************************************");
    }

    public static void main(String[] args) throws Exception {

        System.out.println(
                "*************************************\n" +
                "* Entrust PDF PQ TimeStamp *\n" +
                "*************************************\n");
        CmdArgs cmdArgs = parseArgs(args);

        System.out.println("* Loading PDF document: " + cmdArgs.sourceFile);
        EntrustPdfSignature pdfSignatures = new EntrustPdfSignature(new PdfReader(cmdArgs.sourceFile), cmdArgs.config);
        pdfSignatures.checkSignaturesInfo();

        boolean containsPromise = pdfSignatures.lastContainsPromise();
        if (cmdArgs.destinationFile == null) {
            if( containsPromise ) {
                System.out.println("* Last Document TimeStamp includes a DL TSA Promise");
            }

            if(pdfSignatures.lastContainsProof()) {
                System.out.println("* Last Document TimeStamp includes a DL TSA Proof");
            }
            return;
        }

        DLTSAClient client = new DLTSAClient(pdfSignatures, cmdArgs.config);
        PdfSigner signer = new PdfSigner(new PdfReader(cmdArgs.sourceFile), new FileOutputStream(cmdArgs.destinationFile), new StampingProperties().useAppendMode());
        signer.timestamp(client, "Entrust TSA (Sig" + pdfSignatures.getNumberSignatures() + ")");

        System.out.println("* TimeStamped document saved in " + cmdArgs.destinationFile);
        exit(0);
    }

}