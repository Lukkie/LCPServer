/**
 * Created by Lukas on 30-Mar-16.
 */

import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;

import java.io.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;

/**
 * Used by certificate GUI
 */
public class CertificateParser {

    private byte[] cardECCertificate = new byte[] { (byte) 0x30, (byte) 0x82, (byte) 0x02, (byte) 0x47,
                                                             (byte) 0x30, (byte) 0x82, (byte) 0x01, (byte) 0x2f, (byte) 0x02, (byte) 0x04, (byte) 0xaf, (byte) 0xaa,
                                                             (byte) 0xf1, (byte) 0x5e, (byte) 0x30, (byte) 0x0d, (byte) 0x06, (byte) 0x09, (byte) 0x2a, (byte) 0x86,
                                                             (byte) 0x48, (byte) 0x86, (byte) 0xf7, (byte) 0x0d, (byte) 0x01, (byte) 0x01, (byte) 0x05, (byte) 0x05,
                                                             (byte) 0x00, (byte) 0x30, (byte) 0x53, (byte) 0x31, (byte) 0x13, (byte) 0x30, (byte) 0x11, (byte) 0x06,
                                                             (byte) 0x03, (byte) 0x55, (byte) 0x04, (byte) 0x03, (byte) 0x0c, (byte) 0x0a, (byte) 0x77, (byte) 0x77,
                                                             (byte) 0x77, (byte) 0x2e, (byte) 0x4c, (byte) 0x43, (byte) 0x50, (byte) 0x2e, (byte) 0x62, (byte) 0x65,
                                                             (byte) 0x31, (byte) 0x11, (byte) 0x30, (byte) 0x0f, (byte) 0x06, (byte) 0x03, (byte) 0x55, (byte) 0x04,
                                                             (byte) 0x0a, (byte) 0x0c, (byte) 0x08, (byte) 0x4b, (byte) 0x55, (byte) 0x4c, (byte) 0x65, (byte) 0x75,
                                                             (byte) 0x76, (byte) 0x65, (byte) 0x6e, (byte) 0x31, (byte) 0x0d, (byte) 0x30, (byte) 0x0b, (byte) 0x06,
                                                             (byte) 0x03, (byte) 0x55, (byte) 0x04, (byte) 0x07, (byte) 0x0c, (byte) 0x04, (byte) 0x47, (byte) 0x65,
                                                             (byte) 0x6e, (byte) 0x74, (byte) 0x31, (byte) 0x0d, (byte) 0x30, (byte) 0x0b, (byte) 0x06, (byte) 0x03,
                                                             (byte) 0x55, (byte) 0x04, (byte) 0x08, (byte) 0x0c, (byte) 0x04, (byte) 0x4f, (byte) 0x2d, (byte) 0x56,
                                                             (byte) 0x6c, (byte) 0x31, (byte) 0x0b, (byte) 0x30, (byte) 0x09, (byte) 0x06, (byte) 0x03, (byte) 0x55,
                                                             (byte) 0x04, (byte) 0x06, (byte) 0x13, (byte) 0x02, (byte) 0x42, (byte) 0x45, (byte) 0x30, (byte) 0x1e,
                                                             (byte) 0x17, (byte) 0x0d, (byte) 0x31, (byte) 0x36, (byte) 0x30, (byte) 0x33, (byte) 0x32, (byte) 0x31,
                                                             (byte) 0x30, (byte) 0x38, (byte) 0x35, (byte) 0x35, (byte) 0x34, (byte) 0x37, (byte) 0x5a, (byte) 0x17,
                                                             (byte) 0x0d, (byte) 0x31, (byte) 0x36, (byte) 0x30, (byte) 0x36, (byte) 0x32, (byte) 0x39, (byte) 0x30,
                                                             (byte) 0x38, (byte) 0x35, (byte) 0x35, (byte) 0x34, (byte) 0x37, (byte) 0x5a, (byte) 0x30, (byte) 0x58,
                                                             (byte) 0x31, (byte) 0x18, (byte) 0x30, (byte) 0x16, (byte) 0x06, (byte) 0x03, (byte) 0x55, (byte) 0x04,
                                                             (byte) 0x03, (byte) 0x0c, (byte) 0x0f, (byte) 0x77, (byte) 0x77, (byte) 0x77, (byte) 0x2e, (byte) 0x4a,
                                                             (byte) 0x61, (byte) 0x76, (byte) 0x61, (byte) 0x63, (byte) 0x61, (byte) 0x72, (byte) 0x64, (byte) 0x2e,
                                                             (byte) 0x62, (byte) 0x65, (byte) 0x31, (byte) 0x11, (byte) 0x30, (byte) 0x0f, (byte) 0x06, (byte) 0x03,
                                                             (byte) 0x55, (byte) 0x04, (byte) 0x0a, (byte) 0x0c, (byte) 0x08, (byte) 0x4b, (byte) 0x55, (byte) 0x4c,
                                                             (byte) 0x65, (byte) 0x75, (byte) 0x76, (byte) 0x65, (byte) 0x6e, (byte) 0x31, (byte) 0x0d, (byte) 0x30,
                                                             (byte) 0x0b, (byte) 0x06, (byte) 0x03, (byte) 0x55, (byte) 0x04, (byte) 0x07, (byte) 0x0c, (byte) 0x04,
                                                             (byte) 0x47, (byte) 0x65, (byte) 0x6e, (byte) 0x74, (byte) 0x31, (byte) 0x0d, (byte) 0x30, (byte) 0x0b,
                                                             (byte) 0x06, (byte) 0x03, (byte) 0x55, (byte) 0x04, (byte) 0x08, (byte) 0x0c, (byte) 0x04, (byte) 0x4f,
                                                             (byte) 0x2d, (byte) 0x56, (byte) 0x6c, (byte) 0x31, (byte) 0x0b, (byte) 0x30, (byte) 0x09, (byte) 0x06,
                                                             (byte) 0x03, (byte) 0x55, (byte) 0x04, (byte) 0x06, (byte) 0x13, (byte) 0x02, (byte) 0x42, (byte) 0x45,
                                                             (byte) 0x30, (byte) 0x49, (byte) 0x30, (byte) 0x13, (byte) 0x06, (byte) 0x07, (byte) 0x2a, (byte) 0x86,
                                                             (byte) 0x48, (byte) 0xce, (byte) 0x3d, (byte) 0x02, (byte) 0x01, (byte) 0x06, (byte) 0x08, (byte) 0x2a,
                                                             (byte) 0x86, (byte) 0x48, (byte) 0xce, (byte) 0x3d, (byte) 0x03, (byte) 0x01, (byte) 0x01, (byte) 0x03,
                                                             (byte) 0x32, (byte) 0x00, (byte) 0x04, (byte) 0xfb, (byte) 0xfe, (byte) 0xb4, (byte) 0x69, (byte) 0x25,
                                                             (byte) 0x23, (byte) 0x46, (byte) 0x94, (byte) 0x74, (byte) 0x9c, (byte) 0x62, (byte) 0xf5, (byte) 0x04,
                                                             (byte) 0x3d, (byte) 0x01, (byte) 0x62, (byte) 0x0c, (byte) 0x58, (byte) 0x06, (byte) 0xe5, (byte) 0x65,
                                                             (byte) 0x02, (byte) 0x29, (byte) 0x92, (byte) 0xe1, (byte) 0x36, (byte) 0x35, (byte) 0x2e, (byte) 0x67,
                                                             (byte) 0x65, (byte) 0x51, (byte) 0x69, (byte) 0x57, (byte) 0xd1, (byte) 0xd6, (byte) 0xa5, (byte) 0xfe,
                                                             (byte) 0xeb, (byte) 0x8e, (byte) 0xcc, (byte) 0xde, (byte) 0xb1, (byte) 0xa7, (byte) 0xd9, (byte) 0xe7,
                                                             (byte) 0xc1, (byte) 0xbc, (byte) 0xbd, (byte) 0x30, (byte) 0x0d, (byte) 0x06, (byte) 0x09, (byte) 0x2a,
                                                             (byte) 0x86, (byte) 0x48, (byte) 0x86, (byte) 0xf7, (byte) 0x0d, (byte) 0x01, (byte) 0x01, (byte) 0x05,
                                                             (byte) 0x05, (byte) 0x00, (byte) 0x03, (byte) 0x82, (byte) 0x01, (byte) 0x01, (byte) 0x00, (byte) 0xda,
                                                             (byte) 0xac, (byte) 0xf1, (byte) 0x7b, (byte) 0x91, (byte) 0x01, (byte) 0x71, (byte) 0x1e, (byte) 0x2b,
                                                             (byte) 0x29, (byte) 0x4e, (byte) 0x94, (byte) 0x43, (byte) 0x60, (byte) 0xff, (byte) 0x8b, (byte) 0xf0,
                                                             (byte) 0x20, (byte) 0x60, (byte) 0x73, (byte) 0xc9, (byte) 0xb6, (byte) 0xf7, (byte) 0x88, (byte) 0x65,
                                                             (byte) 0x85, (byte) 0x21, (byte) 0x3f, (byte) 0xde, (byte) 0x15, (byte) 0xa8, (byte) 0xda, (byte) 0x81,
                                                             (byte) 0x37, (byte) 0x18, (byte) 0xfb, (byte) 0x20, (byte) 0x9f, (byte) 0xf8, (byte) 0x36, (byte) 0xf6,
                                                             (byte) 0xef, (byte) 0x70, (byte) 0x8e, (byte) 0xa8, (byte) 0xe6, (byte) 0xc0, (byte) 0x31, (byte) 0x0b,
                                                             (byte) 0x18, (byte) 0x60, (byte) 0x73, (byte) 0x8c, (byte) 0x51, (byte) 0xa1, (byte) 0x4b, (byte) 0xfe,
                                                             (byte) 0x3e, (byte) 0xc7, (byte) 0xe7, (byte) 0xf0, (byte) 0x2c, (byte) 0x62, (byte) 0x68, (byte) 0xf5,
                                                             (byte) 0x4d, (byte) 0x3e, (byte) 0x11, (byte) 0x19, (byte) 0x4d, (byte) 0xc5, (byte) 0x80, (byte) 0x5e,
                                                             (byte) 0x77, (byte) 0x2b, (byte) 0x49, (byte) 0x7d, (byte) 0x60, (byte) 0x72, (byte) 0xbf, (byte) 0x5e,
                                                             (byte) 0x75, (byte) 0xae, (byte) 0x93, (byte) 0xd8, (byte) 0x04, (byte) 0xc2, (byte) 0x0f, (byte) 0x2b,
                                                             (byte) 0xdc, (byte) 0x8f, (byte) 0x12, (byte) 0x26, (byte) 0x8b, (byte) 0x23, (byte) 0xe7, (byte) 0xc6,
                                                             (byte) 0xca, (byte) 0x25, (byte) 0x69, (byte) 0xb2, (byte) 0xd5, (byte) 0x78, (byte) 0xec, (byte) 0x9a,
                                                             (byte) 0x50, (byte) 0xb6, (byte) 0x4a, (byte) 0xe7, (byte) 0x6c, (byte) 0x8e, (byte) 0x43, (byte) 0x6f,
                                                             (byte) 0x01, (byte) 0xe6, (byte) 0x39, (byte) 0x19, (byte) 0x6b, (byte) 0x18, (byte) 0xbb, (byte) 0x6b,
                                                             (byte) 0xac, (byte) 0x98, (byte) 0x28, (byte) 0x9a, (byte) 0xd6, (byte) 0x3d, (byte) 0x36, (byte) 0xb7,
                                                             (byte) 0x2b, (byte) 0x2f, (byte) 0xfb, (byte) 0xde, (byte) 0x89, (byte) 0x91, (byte) 0x1b, (byte) 0x85,
                                                             (byte) 0xd2, (byte) 0x22, (byte) 0x74, (byte) 0xde, (byte) 0xd2, (byte) 0x82, (byte) 0x3e, (byte) 0x08,
                                                             (byte) 0x34, (byte) 0xdd, (byte) 0x90, (byte) 0x95, (byte) 0xc2, (byte) 0xaa, (byte) 0x33, (byte) 0x2e,
                                                             (byte) 0x19, (byte) 0x59, (byte) 0x0a, (byte) 0x70, (byte) 0xbc, (byte) 0x1f, (byte) 0x0e, (byte) 0xcd,
                                                             (byte) 0x3d, (byte) 0xc5, (byte) 0x14, (byte) 0xd1, (byte) 0x81, (byte) 0x97, (byte) 0x61, (byte) 0x0a,
                                                             (byte) 0xfa, (byte) 0xe1, (byte) 0x8a, (byte) 0x89, (byte) 0x06, (byte) 0xd4, (byte) 0xb2, (byte) 0x37,
                                                             (byte) 0x97, (byte) 0x2a, (byte) 0x84, (byte) 0x21, (byte) 0xaf, (byte) 0x1a, (byte) 0x23, (byte) 0x12,
                                                             (byte) 0x60, (byte) 0xe6, (byte) 0x7b, (byte) 0xc6, (byte) 0xb3, (byte) 0xfb, (byte) 0xba, (byte) 0x57,
                                                             (byte) 0xc1, (byte) 0x39, (byte) 0x86, (byte) 0x4a, (byte) 0x89, (byte) 0xe5, (byte) 0xb4, (byte) 0x9f,
                                                             (byte) 0xe7, (byte) 0x7c, (byte) 0x75, (byte) 0xa0, (byte) 0x9e, (byte) 0xfe, (byte) 0x58, (byte) 0x70,
                                                             (byte) 0xeb, (byte) 0x8e, (byte) 0x46, (byte) 0xa7, (byte) 0x12, (byte) 0x51, (byte) 0x83, (byte) 0xc6,
                                                             (byte) 0xe6, (byte) 0x30, (byte) 0x81, (byte) 0x75, (byte) 0x3c, (byte) 0xd6, (byte) 0xd5, (byte) 0xd0,
                                                             (byte) 0xaa, (byte) 0x35, (byte) 0x78, (byte) 0x3d, (byte) 0x34, (byte) 0x77, (byte) 0x7e, (byte) 0x18,
                                                             (byte) 0x55, (byte) 0x17, (byte) 0x88, (byte) 0x82, (byte) 0xe2, (byte) 0x01, (byte) 0x8d, (byte) 0x4e,
                                                             (byte) 0xf9, (byte) 0x2f, (byte) 0x83, (byte) 0x37, (byte) 0x94, (byte) 0xf2, (byte) 0x13, (byte) 0x97,
                                                             (byte) 0x46, (byte) 0x17, (byte) 0x18, (byte) 0x6a, (byte) 0x36, (byte) 0x11, (byte) 0x2d };
    private ArrayList<X509Certificate> certificates;

    public CertificateParser() {
        this.certificates = new ArrayList<>();
    }

    public ArrayList<String> getCertificateSubjects() {
        ArrayList<String> subjects = new ArrayList<String>();
        for (X509Certificate c: certificates) {
            X500Name x500name = null;
            try {
                x500name = new JcaX509CertificateHolder(c).getSubject();
            } catch (CertificateEncodingException e) {
                e.printStackTrace();
            }
            RDN cn = x500name.getRDNs(BCStyle.CN)[0];

            subjects.add(IETFUtils.valueToString(cn.getFirst().getValue()));
        }
        return subjects;
    }

    public X509Certificate getCertificate(int index) {
        return certificates.get(index);
    }

    public void parseCertificates() {
        //TODO: info van card inlezen en toevoegen (maar 1 entry)
        X509Certificate certificate = Tools.bytesToCertificate(cardECCertificate);
        certificates.add(certificate);

        // .data files van shops inlezen en toevoegen
        File configFile = new File("data\\config.txt");
        try {
            BufferedReader br = new BufferedReader(new FileReader(configFile));
            String s = null;
            while ((s = br.readLine()) != null) {
                if (s.charAt(0) == '%') continue;
                String name = s.split("=")[0];

                if (!name.equals("LCP") && !name.equals("Client ")) try {
                    loadShopCertificate(name);
                } catch (ClassNotFoundException e) {
                    e.printStackTrace();
                }

            }
            br.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void loadShopCertificate(String shopName) throws IOException, ClassNotFoundException {
        File file = new File("data\\" + shopName +".data");
        FileInputStream in = new FileInputStream(file);
        ObjectInputStream ois = new ObjectInputStream(in);
        ois.readObject();
        ois.readObject();
        byte[] certificateBytes = (byte[])ois.readObject();
        ois.close();

        X509Certificate certificate = Tools.bytesToCertificate(certificateBytes);
        certificates.add(certificate);

    }
}
