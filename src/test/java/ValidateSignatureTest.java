import java.io.File;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.Iterator;

import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.junit.Assert;
import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.codec.Hex;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import cosmic.showdown.x509.X509KeyFinder;

public class ValidateSignatureTest {

    @Test
    public void validateXMLSignature_bankId() throws Exception {

        Path signatureXMLPath = Paths.get("src","test","resources", "signature.xml");
        File signatureXML = signatureXMLPath.toFile();

        XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");

        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        org.w3c.dom.Document document = dbf.newDocumentBuilder().parse(signatureXML);

        NodeList nl = document.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
        if (nl.getLength() == 0) {
            throw new Exception("Cannot find Signature element");
        }

        DOMValidateContext valContext = new DOMValidateContext(new X509KeyFinder(), nl.item(0));

        final NodeList elements = document.getElementsByTagName("bankIdSignedData");
        if (elements.getLength() > 0) {
            valContext.setIdAttributeNS((Element) elements.item(0), null, "Id");
        }

        XMLSignature signature = fac.unmarshalXMLSignature(valContext);

        boolean coreValidity = signature.validate(valContext);

        if (!coreValidity) {
            System.err.println("Signature failed core validation");
            boolean sv = signature.getSignatureValue().validate(valContext);
            System.out.println("signature validation status: " + sv);
            if (!sv) {
                Iterator<Reference> i = signature.getSignedInfo().getReferences().iterator();
                for (int j=0; i.hasNext(); j++) {
                    boolean refValid = (i.next()).validate(valContext);
                    System.out.println("ref["+j+"] validity status: " + refValid);
                }
            }
        } else {
            System.out.println("Signature passed core validation");
        }
    }

    @Test
    public void validateXMLSignature_purchaseOrder() throws Exception {

        Path signatureXMLPath = Paths.get("src","test","resources", "signedPurchaseOrder.xml");
        File signatureXML = signatureXMLPath.toFile();

        XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");

        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        org.w3c.dom.Document document = dbf.newDocumentBuilder().parse(signatureXML);

        document.getDocumentElement().normalize();

        NodeList nl = document.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
        if (nl.getLength() == 0) {
            throw new Exception("Cannot find Signature element");
        }

        DOMValidateContext valContext = new DOMValidateContext(new X509KeyFinder(), nl.item(0));

        XMLSignature signature = fac.unmarshalXMLSignature(valContext);

        boolean coreValidity = signature.validate(valContext);

        if (!coreValidity) {
            System.err.println("Signature failed core validation");
            boolean sv = signature.getSignatureValue().validate(valContext);
            System.out.println("signature validation status: " + sv);
            if (!sv) {
                Iterator<Reference> i = signature.getSignedInfo().getReferences().iterator();
                for (int j=0; i.hasNext(); j++) {
                    boolean refValid = (i.next()).validate(valContext);
                    System.out.println("ref["+j+"] validity status: " + refValid);
                }
            }
        } else {
            System.out.println("Signature passed core validation");
        }
    }

    @Test
    public void hashAndBase64() throws Exception {

        Path signatureXMLPath = Paths.get("src","test","resources", "signeddata.xml");
        File signeddataXML = signatureXMLPath.toFile();

        DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
        DocumentBuilder documentBuilder = documentBuilderFactory.newDocumentBuilder();

        org.w3c.dom.Document document = documentBuilder.parse(signeddataXML);

        // Canonicalization, men gör ingen skillnad
        document.getDocumentElement().normalize();

        TransformerFactory tf = TransformerFactory.newInstance();
        Transformer transformer = tf.newTransformer();
        transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
        StringWriter writer = new StringWriter();
        transformer.transform(new DOMSource(document), new StreamResult(writer));

        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] encodedhHash = digest.digest(writer.toString().getBytes(StandardCharsets.UTF_8));

        String hashInHex = new String(Hex.encode(encodedhHash));

        String base64digest = new String(Base64.getEncoder().encode(encodedhHash));

        Assert.assertEquals("vNW84PZigGwyj9SI8Ss/ZH8qha+F3fImS8v35S9sHQk=", base64digest);
    }
}