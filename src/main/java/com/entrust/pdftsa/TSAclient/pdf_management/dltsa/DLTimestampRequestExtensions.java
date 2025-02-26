package com.entrust.pdftsa.TSAclient.pdf_management.dltsa;


import java.io.IOException;
import java.util.Base64;

import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.tsp.TimeStampToken;

public class DLTimestampRequestExtensions extends Extensions {

  private static final String DL_PROMISE_OID = "2.5.29.69";

  public DLTimestampRequestExtensions(Extension[] extensions) {
    super(extensions);
  }

  public static String getDLAttestation(TimeStampToken timestampToken) throws IOException {
    AttributeTable unsignedAttributes = timestampToken.getUnsignedAttributes();
    try {
        Attribute attribute = unsignedAttributes.get(new ASN1ObjectIdentifier(DL_PROMISE_OID));
        return getDLAttestation(attribute);
    }catch (Exception e){
        return null;
    }
  }

  public static String getDLAttestation(Attribute attribute) throws IOException {
    try {
      ASN1Encodable[] dlSet = attribute.getAttributeValues();
      ASN1Encodable asn1Encodable = dlSet[0];
      DLSequence dlSequence = (DLSequence) asn1Encodable;
      DEROctetString derOctetString = (DEROctetString) dlSequence.getObjectAt(2);
      byte[] byteArray = derOctetString.getOctetStream().readAllBytes();
      return  Base64.getUrlEncoder().encodeToString(byteArray);
    }catch (Exception e){
      return null;
    }
  }

  public static byte[] getPromises(TimeStampToken timestampToken) throws Exception {
    AttributeTable unsignedAttributes = timestampToken.getUnsignedAttributes();
    DERSequence promisesSequence = null;
    try {
      ASN1Encodable[] promisesValues = unsignedAttributes.get(new ASN1ObjectIdentifier(DL_PROMISE_OID))
              .getAttributeValues();
      promisesSequence = new DERSequence(promisesValues);
    }catch (Exception e){
      return null;
    }
    return promisesSequence.getEncoded();
  }

  public static byte[] getPromises(Attribute attribute) throws Exception {
    DERSequence promisesSequence = null;
    try {
      ASN1Encodable[] promisesValues = attribute.getAttributeValues();
      promisesSequence = new DERSequence(promisesValues);
    }catch (Exception e){
      return null;
    }
    return promisesSequence.getEncoded();
  }

  public static DLTimestampRequestExtensions createExtensionsWithPromises(TimeStampToken timestampToken) throws Exception {
    byte[] promises = getPromises(timestampToken);
    if (promises == null){
      return null;
    }
    Extension extension = new Extension(
        new ASN1ObjectIdentifier(DL_PROMISE_OID),
        ASN1Boolean.FALSE,
        new DEROctetString(promises));
    return new DLTimestampRequestExtensions(new Extension[] { extension });
  }

  public static DLTimestampRequestExtensions createExtensionsWithPromises(Attribute attribute) throws Exception {
    byte[] promises = getPromises(attribute);
    if (promises == null){
      return null;
    }
    Extension extension = new Extension(
            new ASN1ObjectIdentifier(DL_PROMISE_OID),
            ASN1Boolean.FALSE,
            new DEROctetString(promises));
    return new DLTimestampRequestExtensions(new Extension[] { extension });
  }  
}
