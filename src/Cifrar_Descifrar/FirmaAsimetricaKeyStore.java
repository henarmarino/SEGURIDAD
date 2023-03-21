package Cifrar_Descifrar;

import java.io.*;
import java.security.*;
import java.security.cert.*;

public class FirmaAsimetricaKeyStore {
	
    static String provider = "SunJCE"; 
    static String algoritmo = "SHA256withRSA"; 
    static int longbloque;
    static byte bloque[] = new byte[1024];
    static long filesize = 0;
    static String path = "./documentosCrypto/";
    
    
    public static boolean verificacionAsimetrica(byte[] datosAVerificar, byte[] firmaComprobar, PublicKey publicKey, X509Certificate cert) throws NoSuchAlgorithmException, SignatureException, IOException, InvalidKeyException, KeyStoreException, CertificateException {
    	 
    	/*******************************************************************
    	*       Verificacion
    	******************************************************************/
    	System.out.println("\n ************************************* ");
    	System.out.println(" *           VERIFICACION            * ");
    	System.out.println(" ************************************* \n");
       
    	
    	FileOutputStream bytesAVerificar= new FileOutputStream(path+"datosAVerificar.txt");
    	bytesAVerificar.write(datosAVerificar);
    	bytesAVerificar.close();
    	
    	FileInputStream fmensaje = new FileInputStream(path+"datosAVerificar.txt");
        // Obtener la clave publica del keystore
        // PublicKey publicKey = ks.getCertificate(entry_alias).getPublicKey();

        System.out.println(" CLAVE PUBLICA");	
               
    	// Creamos un objeto para verificar, pasandole el algoritmo leido del certificado.
        
    	Signature verifier=Signature.getInstance(cert.getSigAlgName());	 
    	
        // Inicializamos el objeto para verificar
    	
        verifier.initVerify(publicKey);
        
        while ((longbloque = fmensaje.read(bloque)) > 0) {
            filesize = filesize + longbloque;    		     
        	verifier.update(bloque,0,longbloque);
        }  

    	boolean resultado = false;
    	
    	resultado = verifier.verify(firmaComprobar);
    	
    	if (resultado == true) 
    	    System.out.println(" VERIFICACIÓN DE LA FIRMA CORRECTA");
    	else
    		System.out.println(" FALLO EN LA VERIFICACIÓN DE LA FIRMA");	    
    	
    	fmensaje.close();
    	
    	return resultado;
    	
    }
    
    public static byte[] firmaAsimetrica(byte[] mensajeFirmar,PrivateKey privateKey) throws IOException, GeneralSecurityException {
    	
		System.out.println("\n ******************************************* ");
    	System.out.println(" *                 FIRMA    	           * ");
    	System.out.println(" ******************************************* \n");

    	FileOutputStream bytesAFirmar = new FileOutputStream(path+"datosAFirmar.txt");
    	bytesAFirmar.write(mensajeFirmar);
    	bytesAFirmar.close();
    	
    	FileInputStream ffirma = new FileInputStream(path+"datosAFirmar.txt");
    	

        // Visualizar clave privada
        System.out.println(" CLAVE PRIVADA");	
    	System.out.println(" Algoritmo de Firma (sin el Hash): " + privateKey.getAlgorithm());

    	// Creamos un objeto para firmar/verificar   	
        Signature signer = Signature.getInstance(algoritmo);

        // Inicializamos el objeto para firmar
        signer.initSign(privateKey);
    	
    	// Para firmar primero pasamos el hash al mensaje (metodo "update")
        // y despues firmamos el hash (metodo sign).

        byte[] firma = null;
    	
        while ((longbloque = ffirma.read(bloque)) > 0) {
            filesize = filesize + longbloque;    		     
        	signer.update(bloque,0,longbloque);
        }  

    	firma = signer.sign();
    	
    	double  v = firma.length;
    	
    	System.out.println( " FIRMA: ");

    	ffirma.close();
    	
    	return firma;
    	
    } // Firma Asimetrica
    
}