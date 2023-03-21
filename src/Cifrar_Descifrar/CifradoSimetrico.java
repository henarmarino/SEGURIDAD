package Cifrar_Descifrar;
/**********************************************************************
Nombre:
	Cifrar_Descifrar_Simetrico_SunJCE_v1.0

Descripcion:
	Codigo JAVA para cifrar y descifrar un fichero, usando cualquiera
	de los algoritmos de cifrado simetrico del provider “SunJCE”, tanto
	de cifrado en bloque como de cifrado en flujo.

Notas de uso:
               1. No valido para cifrado PBE
               2. Permite medir el tiempo y velocidad de cifrado.

Fecha:
	28/11/2012
Autor: 
          	Francisco J. Fernandez Masaguer
	ETSI TELECOMUNACION VIGO
	Departamento Ingenieria Telematica
 	email: francisco.fernandez@det.uvigo.es

          Asignatura:
	SEGURIDAD.  3º GETT.   Curso  2012/2013. 

***********************************************************/

import java.io.*;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;


public class CifradoSimetrico {

	static String provider = "SunJCE";  
	static byte bloqueclaro[] = new byte[2024];
	static byte bloquecifrado[] = new byte[2048];
	static String algoritmo = "AES"; 
	static String algoritmoServidor = "DES";
	static String transformacion = "/CBC/PKCS5Padding";
	static String transformacionServidor = "/CFB/NoPadding";
	static int longclave = 196;
	static int longclaveSer = 56;
	static int longbloque;
	static int i;
	static double t, tbi,tbf;		// tiempos totales y por bucle
	static double lf;              // longitud del fichero
	static String path = "./documentosCrypto/";

	public static byte[] cifradoSimetrico(byte[] datosACifrar,  SecretKeySpec ks) throws IOException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, InvalidKeyException {
		/************************************************************
		CIFRAR
		************************************************************/
		FileOutputStream bytesACifrar = new FileOutputStream(path+"bytesACifrarCifradoSimetrico.txt");
		bytesACifrar.write(datosACifrar);
		bytesACifrar.close();
   	
		FileInputStream archivoClaro = new FileInputStream(path+"bytesACifrarCifradoSimetrico.txt");
		ByteArrayOutputStream cifrado = new ByteArrayOutputStream();
		
		FileOutputStream fparametros = new FileOutputStream(path+"parametros.txt");
		
   		System.out.println(" INICIO CIFRADO " + algoritmo + "-" + longclave + "");
	
		Cipher cifrador = Cipher.getInstance(algoritmo + transformacion);

   		// Se cifra con la modalidad opaca de la clave
		cifrador.init(Cipher.ENCRYPT_MODE, ks);
   
		i = 0;
		t = 0;
		lf = 0; 
		tbi = 0;
		tbf = 0;

   		while ((longbloque = archivoClaro.read(bloqueclaro)) > 0) {
        	i++;          
          	lf = lf + longbloque;
           	tbi = System.nanoTime();
			bloquecifrado = cifrador.update(bloqueclaro,0,longbloque);
			tbf = System.nanoTime();
			t = t + tbf - tbi;
			cifrado.write(bloquecifrado);
   		}     
   
		// Hacer dofinal y medir su tiempo
		tbi = System.nanoTime();
		bloquecifrado = cifrador.doFinal();
		tbf = System.nanoTime();

		t = t + tbf - tbi;

		cifrado.write(bloquecifrado);

		// Escribir resultados

		System.out.println(" FIN CIFRADO " + algoritmo + "-" + longclave + " Provider: " + provider + "");


		// Cerrar ficheros
		cifrado.close();
		archivoClaro.close();

		/*******************************************************************
		 *  Obtener parametros del algoritmo y archivarlos
		 *  
		 *  NOTA: Para los cifradores en flujo no se ejecuta el lazo de  
		 *        parametros porque no se necesitan. Ejemplo: RC4
		 *******************************************************************/
		// System.out.println("Leer los parametros(IV,...) usados por el cifrador ..." );

		//AlgorithmParameters  paramxx =  cifrador.getParameters();

	   if (provider.equals("SunJCE") && 
	           ( algoritmo.equals("AES")                    || 
	   		  algoritmo.equals("Blowfish")               || 
	   		  algoritmo.equals("DES")                    || 
	   		  algoritmo.equals("DESede")                 || 
	   		  algoritmo.equals("DiffieHellman")          || 
	   		  algoritmo.equals("OAEP")                   || 
	   		  algoritmo.equals("PBEWithMD5AndDES")       || 
	   		  algoritmo.equals("PBEWithMD5AndTripleDES") || 
	   		  algoritmo.equals("PBEWithSHA1AndDESede")   || 
	   		  algoritmo.equals("PBEWithSHA1AndRC2_40")   || 
	   		  algoritmo.equals("RC2")
	   		  ) )  
	   		{
	   		AlgorithmParameters param = AlgorithmParameters.getInstance(algoritmo);        
	   		param = cifrador.getParameters();
	   		
	   		byte[] paramSerializados = param.getEncoded();
	   		fparametros.write(paramSerializados);
	   		fparametros.close();   		 
			}
	   
	   return cifrado.toByteArray();
	}	// Cifrado Simetrico	
	
	public static byte[] cifradoSimetricoServidor(byte[] datosACifrar,  SecretKeySpec ks) throws IOException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, InvalidKeyException {
		/************************************************************
								CIFRAR
		************************************************************/
		FileOutputStream bytesACifrar = new FileOutputStream(path+"datosACifrarSimetricoServidor.txt");
		bytesACifrar.write(datosACifrar);
		bytesACifrar.close();
   	
		FileInputStream archivoClaro = new FileInputStream(path+"datosACifrarSimetricoServidor.txt");
	 	ByteArrayOutputStream cifrado = new ByteArrayOutputStream();
		
		FileOutputStream fparametros = new FileOutputStream(path+"parametrosServidor.txt");
		
   		System.out.println(" INICIO CIFRADO " + algoritmoServidor + "-" + longclaveSer + "");
	
		Cipher cifrador = Cipher.getInstance(algoritmoServidor + transformacionServidor);

   		// Se cifra con la modalidad opaca de la clave
		cifrador.init(Cipher.ENCRYPT_MODE, ks);
   
		i = 0;
		t = 0;
		lf = 0; 
		tbi = 0;
		tbf = 0;

   		while ((longbloque = archivoClaro.read(bloqueclaro)) > 0) {
        	i++;          
          	lf = lf + longbloque;
           	tbi = System.nanoTime();
			bloquecifrado = cifrador.update(bloqueclaro,0,longbloque);
			tbf = System.nanoTime();
			t = t + tbf - tbi;
			cifrado.write(bloquecifrado);
   		}     
   
		// Hacer dofinal y medir su tiempo
		tbi = System.nanoTime();
		bloquecifrado = cifrador.doFinal();
		tbf = System.nanoTime();

		t = t + tbf - tbi;

		cifrado.write(bloquecifrado);

		// Escribir resultados

		//System.out.println("Long. ultimo bloque" + bloquecifrado.length );
		System.out.println(" FIN CIFRADO " + algoritmoServidor + "-" + longclaveSer + " Provider: " + provider + "");

		// Cerrar ficheros
		cifrado.close();
		archivoClaro.close();

		/*******************************************************************
		 *  Obtener parametros del algoritmo y archivarlos
		 *  
		 *  NOTA: Para los cifradores en flujo no se ejecuta el lazo de  
		 *        parametros porque no se necesitan. Ejemplo: RC4
		 *******************************************************************/
		// System.out.println("Leer los parametros(IV,...) usados por el cifrador ..." );

		//AlgorithmParameters  paramxx =  cifrador.getParameters();

	   if (provider.equals("SunJCE") && 
	           (   algoritmoServidor.equals("AES")                    || 
	    		   algoritmoServidor.equals("Blowfish")               || 
	    		   algoritmoServidor.equals("DES")                    || 
	    		   algoritmoServidor.equals("DESede")                 || 
	    		   algoritmoServidor.equals("DiffieHellman")          || 
	    		   algoritmoServidor.equals("OAEP")                   || 
	    		   algoritmoServidor.equals("PBEWithMD5AndDES")       || 
	    		   algoritmoServidor.equals("PBEWithMD5AndTripleDES") || 
	    		   algoritmoServidor.equals("PBEWithSHA1AndDESede")   || 
	    		   algoritmoServidor.equals("PBEWithSHA1AndRC2_40")   || 
	    		   algoritmoServidor.equals("RC2")
		  ) )  
	   		{
	   		AlgorithmParameters param = AlgorithmParameters.getInstance(algoritmoServidor);        
	   		param = cifrador.getParameters();
	   		 
	   		 	   		byte[] paramSerializados = param.getEncoded();
	   		fparametros.write(paramSerializados);
	   		fparametros.close();   		 
			}
	   
	   return cifrado.toByteArray();
	}	// Cifrado Simetrico Servidor
   
   public static byte[] descifradoSimetrico(byte[] datosADescifrar, SecretKeySpec ks,byte[] parametros) throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, IOException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
	   
		//*****************************************************************************
	    //					DESCIFRAR
	    //*****************************************************************************
	    FileOutputStream bytesALeer = new FileOutputStream(path+"datosADescifrarSimetrico.txt");
		bytesALeer.write(datosADescifrar);
		bytesALeer.close();
   	
		FileInputStream archivoCifrado = new FileInputStream(path+"datosADescifrarSimetrico.txt");
	 	ByteArrayOutputStream descifrado = new ByteArrayOutputStream();
	         
        byte bloquecifrado2[] = new byte[1024];
        byte bloqueclaro2[] = new byte[1048];		

        System.out.println("\n *************** INICIO DESCIFRADO *****************\n" );
	         
	 	Cipher descifrador = Cipher.getInstance(algoritmo + transformacion, provider);

		// Leer los parametros si el algoritmo soporta parametros
		if (provider.equals("SunJCE") && 
				( algoritmo.equals("AES")                    || 
				algoritmo.equals("Blowfish")               || 
				algoritmo.equals("DES")                    || 
				algoritmo.equals("DESede")                 || 
				algoritmo.equals("DiffieHellman")          || 
				algoritmo.equals("OAEP")                   || 
				algoritmo.equals("PBEWithMD5AndDES")       || 
				algoritmo.equals("PBEWithMD5AndTripleDES") || 
				algoritmo.equals("PBEWithSHA1AndDESede")   || 
				algoritmo.equals("PBEWithSHA1AndRC2_40")   || 
				algoritmo.equals("RC2")
			// -- Aqui se introducirian otros algoritmos
				) )  
				{
			AlgorithmParameters params = AlgorithmParameters.getInstance(algoritmo,provider);        
		    params.init(parametros);
		    
            descifrador.init(Cipher.DECRYPT_MODE, ks, params);
	    }
		else{
	       	descifrador.init(Cipher.DECRYPT_MODE, ks);
	    }
	         
		while ((longbloque = archivoCifrado.read(bloquecifrado2)) > 0) {
	        bloqueclaro2 = descifrador.update(bloquecifrado2,0,longbloque);
	        descifrado.write(bloqueclaro2);
	    }

		bloqueclaro2 = descifrador.doFinal();
		descifrado.write(bloqueclaro2);
		
		descifrado.close();

		System.out.println("\n *************** FIN DESCIFRADO *****************\n" ); 
		
		return descifrado.toByteArray();

	}	// Descifrado Simetrico
   
   public static byte[] descifradoSimetricoServidor(byte[] datosADescifrar, SecretKeySpec ks,byte[] parametros) throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, IOException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
	   
		//*****************************************************************************
	    //					DESCIFRAR
	    //*****************************************************************************
	    FileOutputStream bytesALeer = new FileOutputStream(path+"datosADescifrarSimetricoServidor.txt");
		bytesALeer.write(datosADescifrar);
		bytesALeer.close();
  	
		FileInputStream archivoCifrado = new FileInputStream(path+"datosADescifrarSimetricoServidor.txt");
	 	ByteArrayOutputStream descifrado = new ByteArrayOutputStream();
	         
       byte bloquecifrado2[] = new byte[1024];
       byte bloqueclaro2[] = new byte[1048];		

       System.out.println("\n *************** INICIO DESCIFRADO *****************\n" );
	         
	 	Cipher descifrador = Cipher.getInstance(algoritmoServidor + transformacionServidor, provider);

		// Leer los parametros si el algoritmo soporta parametros
		if (provider.equals("SunJCE") && 
				( algoritmoServidor.equals("AES")                    || 
						algoritmoServidor.equals("Blowfish")               || 
						algoritmoServidor.equals("DES")                    || 
						algoritmoServidor.equals("DESede")                 || 
						algoritmoServidor.equals("DiffieHellman")          || 
						algoritmoServidor.equals("OAEP")                   || 
						algoritmoServidor.equals("PBEWithMD5AndDES")       || 
						algoritmoServidor.equals("PBEWithMD5AndTripleDES") || 
						algoritmoServidor.equals("PBEWithSHA1AndDESede")   || 
						algoritmoServidor.equals("PBEWithSHA1AndRC2_40")   || 
						algoritmoServidor.equals("RC2")
			// -- Aqui se introducirian otros algoritmos
				) )  
				{
			AlgorithmParameters params = AlgorithmParameters.getInstance(algoritmoServidor,provider);        
		    params.init(parametros);

           descifrador.init(Cipher.DECRYPT_MODE, ks, params);
	    }
		else{
	       	descifrador.init(Cipher.DECRYPT_MODE, ks);
	    }
	         
		while ((longbloque = archivoCifrado.read(bloquecifrado2)) > 0) {
	        bloqueclaro2 = descifrador.update(bloquecifrado2,0,longbloque);
	        descifrado.write(bloqueclaro2);
	    }

		bloqueclaro2 = descifrador.doFinal();
		descifrado.write(bloqueclaro2);
		
		descifrado.close();

		System.out.println("\n *************** FIN DESCIFRADO *****************\n" ); 
		
		return descifrado.toByteArray();

	}	// Descifrado Simetrico
   
   	public static byte[] obtenerParametros() throws FileNotFoundException, IOException {
   		FileInputStream fparametros_in = new FileInputStream (path+"parametros.txt");
   		byte[] parametros = new byte[fparametros_in.available()];
   		fparametros_in.read(parametros); 
   		fparametros_in.close() ;  		
   		return parametros;
   	}
   	
   	public static byte[] obtenerParametrosServidor() throws FileNotFoundException, IOException {
   		FileInputStream fparametros_in = new FileInputStream (path+"parametrosServidor.txt");
   		byte[] parametros = new byte[fparametros_in.available()];
   		fparametros_in.read(parametros); 
   		fparametros_in.close() ;  		
   		return parametros;
   	}
	   
}















