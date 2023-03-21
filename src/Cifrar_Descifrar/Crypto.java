package Cifrar_Descifrar;

import java.io.*;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

public class Crypto {
	
	public static KeyStore ks;
	public static KeyStore ts;

	public static String bytesToHex(byte[] b) {
	    
		char hexDigit[] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A','B', 'C', 'D', 'E', 'F' };
	    StringBuffer buf = new StringBuffer();
	    for (int j = 0; j < b.length; j++) {
	      buf.append(hexDigit[(b[j] >> 4) & 0x0f]);
	      buf.append(hexDigit[b[j] & 0x0f]);
	    }
	    return buf.toString();
	  }
	

	public static byte[] getBytes(String documento) throws IOException {
	
		String path = "./documentos/";
		
		File archivo = new File(path+documento);
		FileInputStream file = new FileInputStream(archivo);
		DataInputStream data = new DataInputStream(file);
		
		byte[] bytecodes = new byte[(int)archivo.length()];
		data.readFully(bytecodes);
		data.close();
		
		return bytecodes;
	}
	
	public static PublicKey getPublicKey(String trustStoreName, String password, String alias) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, KeyStoreException, CertificateException, IOException {
		//  **************   LEER LA CLAVE PUBLICA  **************************
		String 	raizMios     = "/home/miguel/SEG/";
		FileInputStream trustStoreStream = new FileInputStream(raizMios+trustStoreName);
	    KeyStore trustStore = KeyStore.getInstance("JCEKS");
	    trustStore.load(trustStoreStream, password.toCharArray());
		
		PublicKey publicKey = trustStore.getCertificate(alias).getPublicKey();
		
		return publicKey;	
	}
	
	public static PrivateKey getPrivateKey(KeyStore keyStore, String alias, String password) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, KeyStoreException, UnrecoverableEntryException, CertificateException, IOException {
		//  **************   LEER LA CLAVE PRIVADA  **************************
	    KeyStore.PrivateKeyEntry pkEntry = (KeyStore.PrivateKeyEntry)keyStore.getEntry(alias,new KeyStore.PasswordProtection(password.toCharArray()));
	    PrivateKey privateKey = pkEntry.getPrivateKey();
		return privateKey;
	}
	
	public static SecretKeySpec getClaveSecretaKeyStore(KeyStore keyStore, String alias,String passwordKeyStore) throws NoSuchAlgorithmException, UnrecoverableEntryException, KeyStoreException {
		
		KeyStore.SecretKeyEntry pkEntry = (KeyStore.SecretKeyEntry)
		keyStore.getEntry(alias, new KeyStore.PasswordProtection(passwordKeyStore.toCharArray()));
		
		byte[]  kreg_raw = pkEntry.getSecretKey().getEncoded();
		SecretKeySpec kreg = new SecretKeySpec(kreg_raw, "DES"); 
		
		return	kreg;
	}
	
	
}