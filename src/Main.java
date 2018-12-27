import capability.CapabilityToken;
import capability.HTTPSCapabilityClient;
import context.NGSI_ACTION;
import es.um.security.idm.tokens.Token;
import es.um.security.idm.user.IdMUser;
import es.um.security.idm.user.IdMUserException;
import es.um.security.idm.user.implementation.KeyRockIdMUserClient;
import es.um.security.utilities.CertificateUtil;
import es.um.security.utilities.Protocols;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8DecryptorProviderBuilder;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.pkcs.PKCSException;
import utils.Settings;

import javax.net.ssl.*;
import java.io.*;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;

import java.util.StringTokenizer;

import es.odins.CPAAS.Cpabe;
import java.util.Base64;

public class Main {

    /**
     * The username to authenticate to KeyRock by id.
     */

    static String userName = "fcarrez";

    /**
     * The user's password to authenticate to KeyRock by id.
     */

    static String userPassword = "joseluispass";

    /**
     * Directory containing the certificates.
     */

    static String certsRoot = "certs";

    private static final String fiwarePEP = "https://fiware-dev-keyrock.inf.um.es:1027";
    //    private static final String fiwarePEP = "https://localhost:1027";
    private static final String KEYSTORE_FILE = "client-cpaas-io-odins-es.p12";
    private static final String KEYSTORE_PASSWORD = "eUy7CQCs8m6RS4cgpCV6";
    private static final String CAPABILITY_TOKENS_FOLDER = "capability_tokens/";
    // private static final String[] TRUSTEDCERTS = {"PrivateRootCA.cer", "ca.cer", "UniversidaddeCantabria.cer", "UC.crt"};
    private static final String[] TRUSTEDCERTS = {"PrivateRootCA.cer", "ca.cer"};

    //private final static String CAPABILITY_MANAGER_ADDRESS = "https://platform.sociotal.eu:8443/CapabilityManagerServlet/CapabilityManager";
    private final static String CAPABILITY_MANAGER_ADDRESS = "https://155.54.210.167:8443/capman/CapabilityManager";
    //private final static String CAPABILITY_MANAGER_ADDRESS = "https://localhost:8443/CapabilityManager";

    /* CERTAUTHENTICATION is to indicate if HTTPS connection with Capability Manager is through the use of client certificates, it MUST be
     * false in case of Android client and true in case of WUE */
    private final static boolean CERTAUTHENTICATION = true;

    /* USEDELEGATION is to indicate if this client is acting on behalf the real client, it MUST be false in case of Android client, and true
     * in case of WUE */
    private final static boolean USEDELEGATION = true;


	public static final String masterPublic = "test/masterPublic";
	public static final String masterPrivate = "test/masterPrivate";
	public static final String privFile = "test/privKey";
	//public static final String policy = "juanantonio and admin";
    public static final String[] attrib = {"juanantonio","admin","project:CPAAS"};
    

    public static void main(String[] args) {
//        System.setProperty("https.protocols", "TLSv1.2");
        Security.addProvider(new BouncyCastleProvider());

        Settings settings = new Settings(KEYSTORE_FILE, certsRoot + "/", TRUSTEDCERTS, CAPABILITY_TOKENS_FOLDER,
                KEYSTORE_PASSWORD, "./", CERTAUTHENTICATION, USEDELEGATION);
        HTTPSCapabilityClient cc = new HTTPSCapabilityClient(settings);

        CapabilityToken ct = cc.ownToken(NGSI_ACTION.ANY, "*");

        // 1st: check if we already have this token in disk cache.
        if (ct != null && ct.tokenIsValid()) {
            TestPEPProxy(ct);
        } else {
            // If we do not,
            // 2nd: get certificates to generate an identification token
            ArrayList<X509Certificate> cas_certificates;
            try {
                cas_certificates = new ArrayList<>();
                java.security.cert.X509Certificate ca_cert = CertificateUtil.getCertificate(certsRoot + "/ca.cer");
                if (ca_cert == null) {
                    throw new RuntimeException("Cannot found ca.cer inside " + certsRoot + " directory.");
                }
                cas_certificates.add(ca_cert);
                try {
                    // 3st: Generate a authentication token by id.
                    IdMUser keyrockUser = new KeyRockIdMUserClient(Protocols.HTTPS, cas_certificates, "fiware-dev-keyrock.inf.um.es");
                    Token t = keyrockUser.authenticateById(userName, userPassword);
                    System.out.println("Auth token: "+t.getToken_id());

                    if (t != null) {
                        // 4th: Obtain the CapabilityToken with the Keyrock Auth token:
                        ct = cc.requestCapabilityToken(userName,
                                t.getToken_id(),
                                NGSI_ACTION.ANY,
                                "*",
                                CAPABILITY_MANAGER_ADDRESS);
                        if (ct != null) {
                            // 5th: With the capability token, ask for something to the PEPProxy:
                            TestPEPProxy(ct);
                        } else {
                            throw new RuntimeException("Couldn't get capability token.");
                        }
                    } else {
                        throw new RuntimeException("Token is null");
                    }
                } catch (IdMUserException e) {
                    System.out.println("Could not authenticate by id to the KeyRock.");
                    e.printStackTrace();
                }
            } catch (IOException e) {
                System.out.println("Could not read or process the certificate.");
                e.printStackTrace();
            }

        }
    }

    private static X509Certificate GetPEPProxyServerCert() throws IOException, CertificateException {
        X509Certificate serverCert = null;

        InputStream is = new FileInputStream(certsRoot + "/pep-server-cert.crt");

        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        serverCert = (X509Certificate) cf.generateCertificate(is);

        is.close();

        return serverCert;
    }

    private static PrivateKey loadPrivateKey()
            throws IOException, GeneralSecurityException, OperatorCreationException, PKCSException {
        FileReader fileReader = new FileReader(certsRoot + "/pep-client-key.pem");
        PEMParser keyReader = new PEMParser(fileReader);

        JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
        InputDecryptorProvider decryptionProv = new JceOpenSSLPKCS8DecryptorProviderBuilder().build("jajaja".toCharArray());

        Object keyPair = keyReader.readObject();
        PrivateKeyInfo keyInfo;

        if (keyPair instanceof PKCS8EncryptedPrivateKeyInfo) {
            keyInfo = ((PKCS8EncryptedPrivateKeyInfo) keyPair).decryptPrivateKeyInfo(decryptionProv);
            keyReader.close();
            return converter.getPrivateKey(keyInfo);
        }
        return null;
    }

    private static X509Certificate GetClientCertificateForPEPProxy() throws CertificateException, IOException {
        X509Certificate clientCert = null;

        InputStream is = new FileInputStream(certsRoot + "/pep-client-cert.crt");

        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        clientCert = (X509Certificate) cf.generateCertificate(is);

        is.close();

        return clientCert;
    }

    private static void TestPEPProxy(CapabilityToken ct) {
        try {
            // Read client and server certs to trust.
            X509Certificate clientCert = Main.GetClientCertificateForPEPProxy();
            X509Certificate serverCert = Main.GetPEPProxyServerCert();

            // Server cert will be used to trust
            TrustManagerFactory tmf = TrustManagerFactory
                    .getInstance(TrustManagerFactory.getDefaultAlgorithm());
            KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
            ks.load(null); // You don't need the KeyStore instance to come from a file.

            ks.setCertificateEntry("server", serverCert);

            tmf.init(ks);

            // Client cert and private key will be used to auth as client
            KeyStore clientKs = KeyStore.getInstance(KeyStore.getDefaultType());
            clientKs.load(null); // You don't need the KeyStore instance to come from a file.

            clientKs.setCertificateEntry("client", clientCert);
            clientKs.setKeyEntry("clientKey", loadPrivateKey(), "jajaja".toCharArray(), new X509Certificate[]{clientCert});

            KeyManagerFactory kmf = KeyManagerFactory
                    .getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(clientKs, "jajaja".toCharArray());

            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);

            GenerateTestResourceWithCPABE(ct, sslContext.getSocketFactory());
            AskForResourceToPEPProxy(ct, "Test:2", sslContext.getSocketFactory());

        } catch (IOException | GeneralSecurityException | OperatorCreationException | PKCSException e) {
            e.printStackTrace();
        }
    }

    private static void GenerateTestResourceWithCPABE(CapabilityToken ct, SSLSocketFactory sslFactory) {
        try {
            URL url = new URL(fiwarePEP + "/updateContext");

            // Setting up the HTTP headers
            HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
            conn.setSSLSocketFactory(sslFactory);
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setRequestProperty("Accept", "application/json");
            conn.setRequestProperty("fiware-service", "");
            conn.setRequestProperty("fiware-servicepath", "/");
            // Here we are the capability token
            conn.setRequestProperty("x-auth-token", ct.toString());

            conn.setUseCaches(false);
            conn.setDoInput(true);
            conn.setDoOutput(true);

            conn.connect();

            OutputStream os = conn.getOutputStream();
            BufferedWriter bw = new BufferedWriter(new OutputStreamWriter(os));

            /*{
                "contextElements": [{
                        "entityId": {
                         "id": "Prueba:1",
                         "isPattern": "false",
                         "type": "TipoPrueba"
                        },
                     "attributes": [{
                         "name": "atributoCifrado",
                         "type": "cyphertext",
                         "contextValue": "hola",
                         "metadata": [{
                           "name": "cpabe-policy",
                           "type": "string",
                           "value": "juanantonio and admin"
                         }]
                     }]
                 }],
                 "updateAction": "APPEND"
            } */
            bw.write("{\n" +
                    "   \"contextElements\": [{\n" +
                    "        \"entityId\": {\n" +
                    "            \"type\": \"TipoPrueba\",\n" +
                    "            \"isPattern\": \"false\",\n" +
                    "            \"id\": \"Test:2\"\n" +
                    "         },\n" +
                    "         \"attributes\": [{\n" +
                    "                    \"name\": \"atributoCifrado\",\n" +
                    "                    \"type\": \"cyphertext\",\n" +
                    "                    \"contextValue\": \"hola\",\n" +
                    "                    \"metadata\": [{\n" +
                    "                      \"name\": \"cpabe-policy\",\n" +
                    "                      \"type\": \"string\",\n" +
                    "                      \"value\": \"juanantonio and admin\"\n" +
                    "                    }]\n" +
                    "                }]\n" +
                    "        }],\n" +
                    "    \"updateAction\": \"APPEND\"\n" +
                    "}");
            bw.flush();

            InputStream is = conn.getInputStream();
            BufferedReader br = new BufferedReader(new InputStreamReader(is));
            char[] buffer = new char[1000];
            int leido;
            while ((leido = br.read(buffer)) > 0) {
                System.out.println(new String(buffer, 0, leido));
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static void AskForResourceToPEPProxy(CapabilityToken ct, String id, SSLSocketFactory sslFactory) {
        AskForResourceToPEPProxy(ct, id, "", "/#", sslFactory);
    }

    private static void AskForResourceToPEPProxy(CapabilityToken ct, String id, String fiwareService, String fiwareServicePath, SSLSocketFactory sslFactory) {
        try {
            URL url = new URL(fiwarePEP + "/queryContext");

            // Setting up the HTTP headers
            HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
            conn.setSSLSocketFactory(sslFactory);
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setRequestProperty("Accept", "application/json");
            conn.setRequestProperty("fiware-service", fiwareService);
            conn.setRequestProperty("fiware-servicepath", fiwareServicePath);
            // Here we are the capability token
            conn.setRequestProperty("x-auth-token", ct.toString());

            conn.setUseCaches(false);
            conn.setDoInput(true);
            conn.setDoOutput(true);

            conn.connect();

            OutputStream os = conn.getOutputStream();
            BufferedWriter bw = new BufferedWriter(new OutputStreamWriter(os));


            /*
             *{
                "entities": [
                    {
                       "isPattern": "true",
                       "id": ".*"
                    }
                ]
             }
             */
            bw.write("{" +
                    "\"entities\": [" +
                    "{" +
                    "\"isPattern\": \"true\"," +
                    "\"id\": \"" + id + "\"" +
                    "}" +
                    "]" +
                    "}");
            bw.flush();

            InputStream is = conn.getInputStream();
            BufferedReader br = new BufferedReader(new InputStreamReader(is));
            char[] buffer = new char[2000];
            int leido;
            while ((leido = br.read(buffer)) > 0) {
                System.out.println(new String(buffer, 0, leido));
            }
            System.out.println("**Context Value**");
            String contextValue = new String();
            StringTokenizer st = new StringTokenizer(String.valueOf(buffer), ",");
            while (st.hasMoreElements()) {
                String aux = (String) st.nextElement();
                if (aux.contains("contextValue"))
                {
                    contextValue = aux.substring(16, aux.length() -1);
                    System.out.println(contextValue);

                }
            }
            if (contextValue != null || !contextValue.isEmpty())
            {
                try {
                    String urlDecoded = java.net.URLDecoder.decode(contextValue, "UTF-8");
        
                    
                    byte[] decoded = Base64.getDecoder().decode(urlDecoded);
                    
                    
                    //Cpabe.keygen(masterPublic, masterPrivate,privFile, attrib);
                    
                    byte[] decrypted = Cpabe.decryptMessage(masterPublic, privFile, decoded);
                    System.out.println(new String(decrypted));
                    
                    
                }catch (Exception e) {
                    // TODO Auto-generated catch block
                    e.printStackTrace();
                    System.out.println("error");
                } 
                
                
                System.out.println("done");                
            }

        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
