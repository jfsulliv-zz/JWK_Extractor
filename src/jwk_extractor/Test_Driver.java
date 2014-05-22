package jwk_extractor;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.ArrayList;

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

		JWK_Handler j = new JWK_Handler(args[0], PASS);

		ArrayList<Certificate> certs = (ArrayList<Certificate>) j.getCertificates();
		try {
			String fmt = j.formatCertificates(certs).toJSONString();
			System.out.println("Extracted the following from the certificates: \n" + fmt);
		} catch (CertificateException e) {
			System.out.println("Bad certificate.");
			e.printStackTrace();
		}
		
		System.exit(0);
	}

}
