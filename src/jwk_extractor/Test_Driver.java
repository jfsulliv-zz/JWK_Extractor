package jwk_extractor;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.ArrayList;

import org.json.simple.JSONArray;

/**
 * Test driver for the JWK Extractor.
 *  args[0] must contain the relative filepath to the Keystore.
 * @author james
 *
 */
public class Test_Driver {

	// Password for keystore - Typically this will come from the server environment
	private static final String PASS = "password";

	public static void main(String[] args) {
		
		if(args.length != 1) {
			System.out.println("Must specify a keystore file.");
			System.exit(1);
		}

		JWK_Handler j = new JWK_Handler(args[0], PASS);

		ArrayList<Certificate> certs = null;
		try {
			certs = (ArrayList<Certificate>) j.getCertificates();
			if(certs == null) System.exit(1);
		} catch(FileNotFoundException e){ 
			System.err.println("Error on file: " + e.getMessage());
			System.exit(1);
		} catch (IOException e) {
			System.err.println(e.getMessage());
			System.exit(1);
		}
		try {
			JSONArray fmtCerts = j.formatCertificates(certs);
			String fmt = fmtCerts.toJSONString();
			System.out.println("Extracted the following from the certificates: \n" + fmt);
		} catch (CertificateException e) {
			System.out.println("Bad certificate.");
			System.exit(1);
		}
		
		System.exit(0);
	}

}
