import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.itextpdf.text.DocumentException;

import br.com.poc.service.SignaturesService;

public class Main {
	
	public static String ORIGINAL = "text.pdf";
	public static String SIGNED1 = "signature_1.pdf";

	public static void main(String[] args) {
		
		SignaturesService signaturesService = new SignaturesService();

		try {
			Security.addProvider(new BouncyCastleProvider());

			signaturesService.signPdf(ORIGINAL, SIGNED1);

		} catch (IOException | DocumentException | GeneralSecurityException e) {

			e.printStackTrace();
		}
	}
}