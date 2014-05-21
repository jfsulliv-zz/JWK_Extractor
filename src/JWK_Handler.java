import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.apache.commons.codec.binary.Base64;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

/**
 * Handles extraction of PKI Certificate data from a KeyStore, and formatting this data into
 *  JWK-compliant JSON format.
 *  
 *  SPECIFICATIONS
 *   JWK - JSON Web Key - http://self-issued.info/docs/draft-ietf-jose-json-web-key.html
 *   JWA - JSON Web Algorithm - http://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-26
 *   X509 - PKI Certificate - http://tools.ietf.org/html/rfc5280
 *   
 *   
 * @author james
 *
 */
public class JWK_Handler {
	private Map<String, String> OID_MAP = new HashMap<String, String>();
	
	// Parameter values for the kty field that are defined by the JWK spec
	private static String[] KTY_SPEC = {"EC", "RSA", "oct"};

	private String keystoreLocation;
	private String password;
	
	/* Maps Signature Algorithm Object ID values with a human-readable (JWK Compliant) string 
	 *  Ref. to http://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-26#appendix-A.1
	 */
	private void setup_OID_MAP() {
		OID_MAP.put("1.2.840.113549.2.9", "HS256");
		OID_MAP.put("1.2.840.113549.2.10", "HS384");
		OID_MAP.put("1.2.840.113549.2.11", "HS512");		
		OID_MAP.put("1.2.840.113549.1.1.11", "RS256");
		OID_MAP.put("1.2.840.113549.1.1.12", "RS384");
		OID_MAP.put("1.2.840.113549.1.1.13", "RS512");
		OID_MAP.put("1.2.840.10045.4.3.2", "ES256");
		OID_MAP.put("1.2.840.10045.4.3.3", "ES384");		
		OID_MAP.put("1.2.840.10045.4.3.4", "ES512");
		OID_MAP.put("1.2.840.113549.1.1.10", "PS");
	}

	/**
	 * Constructor for a JWK_Handler to extract PKI Certificate information from a KeyStore.
	 * @param keystoreLocation
	 */
	public JWK_Handler(String keystoreLocation, String passwd) {
		this.keystoreLocation = keystoreLocation;
		this.password = passwd;
		setup_OID_MAP();
	}
	
	/**
	 * Get all certificates that are contained in the Keystore.
	 * 
	 * @return cert[] Array of certificates in the Keystore.
	 */
	public List<Certificate> getCertificates() {
		File file = new File(keystoreLocation);
		FileInputStream is;
		try {
			is = new FileInputStream(file);
		} catch (FileNotFoundException e) {
			System.err.println(e.toString());
			return null;
		}
		
		ArrayList<Certificate> certs = new ArrayList<Certificate>();
		
		try {
			KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
			keystore.load(is, password.toCharArray());

			Enumeration<String> enumeration = keystore.aliases();
			while (enumeration.hasMoreElements()) {
				Certificate cert = keystore.getCertificate(enumeration.nextElement());
				certs.add(cert);
			} 
		} catch (KeyStoreException e) {
			System.err.println(e.toString());
			return null;
		} catch (NoSuchAlgorithmException e) {
			System.err.println(e.toString());
			return null;
		} catch (CertificateException e) {
			System.err.println(e.toString());
			return null;
		} catch (IOException e) {
			System.err.println(e.toString());
			return null;
		}

		return certs;
		
	}

	/**
	 * 	Get the certificate referred to by alias, if it is in the KeyStore.
	 *  
	 *  @param alias a string alias for the given KeyStore entry
	 *  
	 *  @return cert the certificate that is referred to by alias or null if it does not exist
	 */
	public Certificate getCertificate(String alias) {
		File file = new File(keystoreLocation);
		FileInputStream is;
		try {
			is = new FileInputStream(file);
		} catch (FileNotFoundException e) {
			System.err.println(e.toString());
			return null;
		}
		
		Certificate cert = null;
		try {
			KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
			keystore.load(is, password.toCharArray());

			Enumeration<String> enumeration = keystore.aliases();
			while (enumeration.hasMoreElements()) {
				String next = (String) enumeration.nextElement();
				if (alias.equals(next)) {
					cert = keystore.getCertificate(alias);
				}

			} 
		} catch (KeyStoreException e) {
			System.err.println(e.toString());
			return null;
		} catch (NoSuchAlgorithmException e) {
			System.err.println(e.toString());
			return null;
		} catch (CertificateException e) {
			System.err.println(e.toString());
			return null;
		} catch (IOException e) {
			System.err.println(e.toString());
			return null;
		}

		return cert;
	}
	
	/**
	 *  Returns a JWK-Compliant JSONObject containing relevant Certificate information.
	 *  
	 *  @return jsonFmt The JSONObject containing relevant Certificate information.
	 *  
	 *  @throws CertificateException if the certificate is missing, invalid or otherwise unparseable
	 */
	public JSONObject formatCertificate(Certificate cert) throws CertificateException {

		CertificateFactory cf = CertificateFactory.getInstance("X.509");
		ByteArrayInputStream bis = new ByteArrayInputStream(cert.getEncoded());
		X509Certificate xCert = (X509Certificate)cf.generateCertificate(bis);
		
		String use = extractUse(xCert);
		String kty = extractKty(cert);
		String alg = extractAlg(xCert);
		String mod = extractModulus(xCert, kty);
		String exp = extractExponent(xCert, kty);
		
		JSONObject jsonFmt = new JSONObject();
		jsonFmt.put("use", use);
		jsonFmt.put("kty", kty);
		jsonFmt.put("alg", alg);
		jsonFmt.put("mod", mod);
		jsonFmt.put("exp", exp);
		
		return jsonFmt;
		
	}
	
	public JSONArray formatCertificates(List<Certificate> certs) throws CertificateException {
		
		JSONArray jsonAry = new JSONArray();
		jsonAry.add("keys");
		
		Iterator iter = certs.iterator();
		while(iter.hasNext()) {
			Certificate cert = (Certificate)iter.next();
			JSONObject fmt = formatCertificate(cert);
			jsonAry.add(fmt);
		}
		
		return jsonAry;
	}
	
	private String extractKty(Certificate cert) {
		PublicKey pk = cert.getPublicKey();
		
		String kty = "";
		String pkKty = pk.getAlgorithm();
		
		int i = 0;
		boolean done = false;
		while(!done) {
			if(pkKty.equals(KTY_SPEC[i++])) {
				kty = pkKty;
				done = true;
			} else {
				done = (i == KTY_SPEC.length);
			}			
		}
		
		return kty;
	}
	
	private String extractAlg(X509Certificate cert) {
		if(cert == null) return null;
		
		String alg = "";
		
		String oid = cert.getSigAlgOID();
		if(OID_MAP.containsKey(oid)) {
			alg = OID_MAP.get(oid);
		}
		
		return alg;
	}
	
	private String extractUse(X509Certificate cert) {
		if(cert == null) return null;
		
		String use = "";
		boolean[] keyUsage = cert.getKeyUsage();
		if(keyUsage == null) return use;
		
        if (keyUsage[0]) use += "sig";
        if (keyUsage[7]) use += (use.equals("")?"":", ") + "enc";
        if (keyUsage[8]) use += (use.equals("")?"":", ") + "dec";

        return use;
	}
	
	private String extractModulus(X509Certificate cert, String kty) {
		if(cert == null || kty == null) return null;
		
		String mod = "";
		
		RSAPublicKey pk;
		if(kty.equals("RSA")) {
			pk = (RSAPublicKey)cert.getPublicKey();
			byte[] encoded = Base64.encodeInteger(pk.getModulus());
			mod = Base64.encodeBase64URLSafeString(encoded);
		}
		
		return mod;
	}
	
	private String extractExponent(X509Certificate cert, String kty) {
		if(cert == null || kty == null) return null;
		
		String exp = "";
		
		RSAPublicKey pk;
		if(kty.equals("RSA")) {
			pk = (RSAPublicKey)cert.getPublicKey();
			byte[] encoded = Base64.encodeInteger(pk.getPublicExponent());
			exp = Base64.encodeBase64URLSafeString(encoded);
		}
		
		return exp;
	}

}
