package br.com.poc.service;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.MalformedURLException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.itextpdf.text.BadElementException;
import com.itextpdf.text.DocumentException;
import com.itextpdf.text.Image;
import com.itextpdf.text.pdf.BadPdfFormatException;
import com.itextpdf.text.pdf.PdfContentByte;
import com.itextpdf.text.pdf.PdfImage;
import com.itextpdf.text.pdf.PdfIndirectObject;
import com.itextpdf.text.pdf.PdfName;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.PdfSignatureAppearance;
import com.itextpdf.text.pdf.PdfStamper;
import com.itextpdf.text.pdf.security.BouncyCastleDigest;
import com.itextpdf.text.pdf.security.DigestAlgorithms;
import com.itextpdf.text.pdf.security.ExternalDigest;
import com.itextpdf.text.pdf.security.ExternalSignature;
import com.itextpdf.text.pdf.security.MakeSignature;
import com.itextpdf.text.pdf.security.MakeSignature.CryptoStandard;
import com.itextpdf.text.pdf.security.PrivateKeySignature;

public class SignaturesService {

	public static String SIGNED1 = "signature_1.pdf";
	public static String IMG = "selo.png";

	public void signPdf(String src, String dest) throws IOException, DocumentException, GeneralSecurityException {
		String path = "certificado.pfx";
		String keystore_password = "patrick21";
		String key_password = "patrick21";
		KeyStore ks = KeyStore.getInstance("pkcs12", "BC");

		ks.load(new FileInputStream(path), keystore_password.toCharArray());
		String alias = ks.aliases().nextElement();
		PrivateKey key = (PrivateKey) ks.getKey(alias, key_password.toCharArray());
		Certificate[] chain = ks.getCertificateChain(alias);
		PdfReader reader = new PdfReader(src);

		FileOutputStream fout = new FileOutputStream(new File(SIGNED1));

		PdfStamper stp = PdfStamper.createSignature(reader, fout, '\0');

		insertSeal(stp);

		PdfSignatureAppearance sap = stp.getSignatureAppearance();
		sap.setReason("Assinatura Digital.");
		sap.setLocation("Pleber-Christ");

		ExternalDigest digest = new BouncyCastleDigest();
		BouncyCastleProvider provider = new BouncyCastleProvider();
		ExternalSignature signature = new PrivateKeySignature(key, DigestAlgorithms.SHA256, provider.getName());
		MakeSignature.signDetached(sap, digest, signature, chain, null, null, null, 0, CryptoStandard.CMS);

	}

	private void insertSeal(PdfStamper stp) throws BadElementException, MalformedURLException, IOException, BadPdfFormatException, DocumentException {
		Image image = Image.getInstance(IMG);
		PdfImage stream = new PdfImage(image, "", null);
		stream.put(new PdfName("ITXT_SpecialId"), new PdfName("123456789"));
		PdfIndirectObject ref = stp.getWriter().addToBody(stream);
		image.setDirectReference(ref.getIndirectReference());
		image.setAbsolutePosition(0, 0);
		PdfContentByte over = stp.getOverContent(1);
		over.addImage(image);
	}
}