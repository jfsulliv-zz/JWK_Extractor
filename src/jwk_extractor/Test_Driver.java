package jwk_extractor;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.ArrayList;

public class Test_Driver {

	// Password for keystore - Typically this will come from the server environment
	private static final String PASS = "password";

	public static void main(String[] args) {
		if (args.length != 2) {
			System.exit(1);
		}

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
