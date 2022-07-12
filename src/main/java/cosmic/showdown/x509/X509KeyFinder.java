package cosmic.showdown.x509;

import java.security.Key;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Iterator;

import javax.xml.crypto.AlgorithmMethod;
import javax.xml.crypto.KeySelector;
import javax.xml.crypto.KeySelectorException;
import javax.xml.crypto.KeySelectorResult;
import javax.xml.crypto.XMLCryptoContext;
import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.X509Data;

public class X509KeyFinder extends KeySelector {

    public KeySelectorResult select (
        KeyInfo keyInfo,
        KeySelector.Purpose purpose,
        AlgorithmMethod method,
        XMLCryptoContext context) throws KeySelectorException {

        Iterator ki = keyInfo.getContent().iterator();
        while (ki.hasNext()) {
            XMLStructure info = (XMLStructure) ki.next();
            if (!(info instanceof X509Data))
                continue;
            X509Data x509Data = (X509Data) info;
            Iterator xi = x509Data.getContent().iterator();
            while (xi.hasNext()) {
                Object o = xi.next();
                if (!(o instanceof X509Certificate))
                    continue;

                X509Certificate x509Certificate = (X509Certificate) o;

                final PublicKey key = x509Certificate.getPublicKey();

                return new KeySelectorResult() {
                    public Key getKey() { return key; }
                };
            }
        }
        throw new KeySelectorException("No key found!");
    }
}
