import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.nio.charset.Charset;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Key;
import java.security.PublicKey;
import java.security.cert.CertPath;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Iterator;
import java.util.List;

import javax.xml.crypto.KeySelectorResult;
import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.junit.jupiter.api.Test;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import cosmic.showdown.x509.X509KeyFinder;

class ValidateCertificateChainTest {

    @Test
    void validateCertChain() throws Exception {

        Path signatureXMLPath = Paths.get("src","test","resources", "signature2.xml");
        File signatureXML = signatureXMLPath.toFile();

        XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");

        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        org.w3c.dom.Document document = dbf.newDocumentBuilder().parse(signatureXML);

        NodeList nodeList = document.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");

        DOMValidateContext valContext = new DOMValidateContext(new X509KeyFinder(), nodeList.item(0));

        XMLSignature signature = fac.unmarshalXMLSignature(valContext);

        List<X509Certificate> certificateList = new ArrayList<>();

        for (XMLStructure info : signature.getKeyInfo().getContent()) {
            if (!(info instanceof X509Data x509Data))
                continue;
            for (Object o : x509Data.getContent()) {
                if (!(o instanceof X509Certificate))
                    continue;

                certificateList.add((X509Certificate) o);
            }
        }

        /**
         *  Inte riktigt klar
         *
        for (int i=0; i < certificateList.size(); i++) {
            Path certPath = Paths.get("src","test","resources", "cert_" + i + "_.crt");
            File file = certPath.toFile();

            byte[] buf = certificateList.get(i).getEncoded();

            FileOutputStream os = new FileOutputStream(file);
            os.write(buf);
            os.close();

            Writer wr = new OutputStreamWriter(os, Charset.forName("UTF-8"));
            wr.write(Base64.getEncoder().encode(buf));
            wr.flush();
        }

        Path rootCertPath = Paths.get("src","test","resources", "Test_BankID_Root_CA_v1.crt.txt");
        File rootCertFile = rootCertPath.toFile();

        FileInputStream fis = new FileInputStream(rootCertFile);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        Certificate cert = cf.generateCertificate(fis);

        certificateList.add((X509Certificate) cert);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        for (X509Certificate certificate : certificateList) {
            baos.write(certificate.getEncoded());
        }

        byte[] bytes = baos.toByteArray();
        InputStream in = new ByteArrayInputStream(bytes);

        CertPath cp = cf.generateCertPath(in);
        List<Certificate> certs = (List<Certificate>) cp.getCertificates();

        for (X509Certificate x509Certificate : certificateList) {

        }
         */
    }
}
