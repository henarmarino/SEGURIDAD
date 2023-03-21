package Cifrar_Descifrar;

/******************************************************************************
 Nombre: Cifrar_Descifrar_Asimetrico_SunJCE_v1.0

 Descripcion:
                 Codigo JAVA para cifrar y descifrar ASIMETRICO un fichero de texto o binario

 Notas de uso:
                 1. Solo valido para algoritmo RSA 
                 2. Permite medir el tiempo y velocidad de cifrado.

 Fecha:  12/12/2018
 Autor: 
                 Francisco J. Fernandez Masaguer
                 ETSI TELECOMUNACION VIGO
                 Departamento Ingenieria Telematica
                 email: francisco.fernandez@det.uvigo.es

 Asignatura:
                 SEGURIDAD.  3º GETT.   Curso  2018/2019. 

 *****************************************************************************/

import java.io.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.AlgorithmParameters;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;

public class CifradoDescrifradoAsimetrico {

    static String provider = "SunJCE";
    static String algoritmo = "RSA";
    static String transformacion1 = "/ECB/PKCS1Padding"; //Relleno de longitud fija de 88 bits (11 bytes)
    static String transformacion2 = "/ECB/OAEPPadding"; // Este relleno tiene una longitud mayor y es variable
    static int longclave = 2048;                        // NOTA -- Probar a subir este valor e ir viendo como disminuye significativamente la velocidad de descifrado 
    static int longbloque;
    static long t, tbi, tbf;                            // tiempos totales y por bucle
    static double lf;                                   // longitud del fichero
    static String path = "./documentosCrypto/";
        
    public static byte[] cifradoAsimetrico(byte[] datosACifrar, PublicKey publicKey) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException{
        /************************************************************
         * CIFRAR
         ************************************************************/
    	FileOutputStream bytesACifrar = new FileOutputStream(path+"datosACifrarAsimetrico.txt");
		bytesACifrar.write(datosACifrar);
		bytesACifrar.close();
   	
		FileInputStream archivoClaro = new FileInputStream(path+"datosACifrarAsimetrico.txt");
        ByteArrayOutputStream cifrado = new ByteArrayOutputStream();
        
        System.out.println(" INICIO CIFRADO " + algoritmo + "-" + longclave + "");

        byte bloqueclaro[] = new byte[(longclave/8) - 11]; // *** NOTA: Calculo solo valido para relleno PKCS1Padding ****
        byte bloquecifrado[] = new byte[2048];
        
        Cipher cifrador = Cipher.getInstance(algoritmo + transformacion1);

        // Se cifra con la modalidad opaca de la clave
        cifrador.init(Cipher.ENCRYPT_MODE, publicKey);

        // Datos para medidas de velocidad cifrado
        t = 0; lf = 0; tbi = 0;  tbf = 0;

        while ((longbloque = archivoClaro.read(bloqueclaro)) > 0) {

            lf = lf + longbloque;

            tbi = System.nanoTime();
            
            bloquecifrado = cifrador.update(bloqueclaro, 0, longbloque);
            bloquecifrado = cifrador.doFinal();
           
            tbf = System.nanoTime();
            t = t + tbf - tbi;
            
            cifrado.write(bloquecifrado);
        }
        
        // Escribir resultados velocidad cifrado

        System.out.println(" FIN CIFRADO " + algoritmo + "-" + longclave + " Provider: " + provider + "");
        // Cerrar ficheros
        archivoClaro.close();
       
        
        return cifrado.toByteArray();
               
    }// Cifrado Asimetrico

    
    public static byte[] descifradoAsimetrico(byte[] datosADescifrar, PrivateKey privateKey) throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, IOException, InvalidKeyException {
        // *****************************************************************************
        // DESCIFRAR
        // *****************************************************************************

    	FileOutputStream bytesALeer = new FileOutputStream(path+"datosADescifrarAsimetrico.txt");
    	bytesALeer.write(datosADescifrar);
    	bytesALeer.close();
    	
    	FileInputStream archivoCifrado = new FileInputStream(path+"datosADescifrarAsimetrico.txt");
        byte bloquecifrado2[] = new byte[longclave/8];
        byte bloqueclaro2[] = new byte[512];  // *** Buffer sobredimensionado ***
        ByteArrayOutputStream descifrado = new ByteArrayOutputStream();

        System.out.println(" INICIO DESCIFRADO " + algoritmo + "-" + longclave + "");

        Cipher descifrador = Cipher.getInstance(algoritmo + transformacion1, provider);

        descifrador.init(Cipher.DECRYPT_MODE, privateKey);
        
        // Datos para medidas de velocidad descifrado
        t = 0; lf = 0; tbi = 0;  tbf = 0;
  
        while ((longbloque = archivoCifrado.read(bloquecifrado2)) > 0) {  
	        	
            lf = lf + longbloque;

            tbi = System.nanoTime();

            bloqueclaro2 = descifrador.update(bloquecifrado2, 0, longbloque);
            //System.out.println(descifrador.doFinal(bloquecifrado2));
            bloqueclaro2 = descifrador.doFinal();
           

            tbf = System.nanoTime();
            t = t + tbf - tbi;
            
            descifrado.write(bloqueclaro2);
            
        }

        archivoCifrado.close();

        // Escribir resultados medida velocidad descifrado
        System.out.println(" FIN DESCIFRADO " + algoritmo + "-" + longclave + " Provider: " + provider +"");

        
        return descifrado.toByteArray();

    } //descifrado Asimetrico
}