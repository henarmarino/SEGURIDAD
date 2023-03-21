package Principal;

import Mensajes.*;
import Cifrar_Descifrar.*;

import java.util.*;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.CertPathTrustManagerParameters;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;

import java.io.*;
import java.net.*;
import java.nio.*;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXRevocationChecker;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;


public class Cliente {
	
	public static KeyStore ks;
	public static KeyStore ts;
	public static Scanner keyboard = new Scanner(System.in);
	public static Scanner keyboardOCSP = new Scanner(System.in);
	public static String path = "./documentos/";
	public static String pathCifrado = "./textoCifrado/";
	public static String algoritmo = "AES";
	public static int longclave = 192;
	public static HashMap<byte[],byte[]> archivosCliente =new HashMap <byte[],byte[]>();
	public static TreeMap<Integer,byte[]> hashRespuestaServidor =new TreeMap <Integer,byte[]>();
	public static String 	raizMios     = "/home/miguel/SEG/";

	public static void main (String[] args) {
		String[]   cipherSuitesDisponibles = null;
		
		if (args.length != 4) {
			System.out.println(" Los argumentos son: keyStoreFile truststoreFile passwordKeyStore IpOCSPResponder");
			System.exit(-1);
		}
		
		String keyStoreFile = args[0];
		String truststoreFile = args[1];
		String passwordKeyStore = args[2];
		String IpOCSPResponder = args[3];

		try {
			definirAlmacenesCliente(keyStoreFile,passwordKeyStore,truststoreFile);
			int ocsp = menuOCSP();
			while(ocsp!=1 && ocsp!=2 && ocsp!=3) {
				System.out.println(" Has introducido una opción no válida\n");
				ocsp = menuOCSP();
			}
			if(ocsp==1) {
				System.out.println(" HAS SELECCIONADO OCSP\n");
				definirRevocacionOCSP();
				
			}else if(ocsp==2) {
				System.out.println(" HAS SELECCIONADO OCSP STAPLING\n");
				definirRevocacionOCSPStapling();
			}else {
				System.out.println(" NO SE USARÁ REVOCACIÓN\n");
			}
		
			/*
		     * Set up a key manager for client authentication
		     * if asked by the server.  Use the implementation's
		     * default TrustStore and secureRandom routines.
		     */
		    SSLSocketFactory factory = null;
		    
			try {
				SSLContext ctx;
				KeyManagerFactory kmf;
				char[] passphrase = "1234".toCharArray();

				/********************************************************************************
				* Construir un contexto, pasandole el KeyManager y y TrustManager 
				* Al TrustManager se le incorpora el chequeo de certificados revocados por Ocsp. 
				*   
				********************************************************************************/
				// --- Trust manager.
				
				//  1. Crear PKIXRevocationChecker

				CertPathBuilder cpb = CertPathBuilder.getInstance("PKIX");
				PKIXRevocationChecker rc = (PKIXRevocationChecker) cpb.getRevocationChecker();
				rc.setOptions(EnumSet.of(PKIXRevocationChecker.Option.NO_FALLBACK));
				rc.setOcspResponder(new URI("http://"+IpOCSPResponder));  // Aqui poner la ip y puerto donde se haya lanzado el OCSP Responder

				//   2. Crear el truststore 
				
				ts = KeyStore.getInstance("JCEKS");
				ts.load(new FileInputStream(raizMios + truststoreFile), passphrase);
				
				//  3. Crear los parametros PKIX y el PKIXRevocationChecker
				
				PKIXBuilderParameters pkixParams = new PKIXBuilderParameters(ts, new X509CertSelector());
				pkixParams.addCertPathChecker(rc);
				pkixParams.setRevocationEnabled(false); // habilitar la revocacion (por si acaso)
				
				//
				TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
				tmf.init(new CertPathTrustManagerParameters(pkixParams));
				

				// --- Key manager 
				
				kmf = KeyManagerFactory.getInstance("SunX509");
				ks = KeyStore.getInstance("JCEKS");
				ks.load(new FileInputStream(raizMios + keyStoreFile), passwordKeyStore.toCharArray());
				kmf.init(ks, passphrase);
				
				// Crear el contexto
				ctx = SSLContext.getInstance("TLS");		
				ctx.init(kmf.getKeyManagers(),  
						 null,//tmf.getTrustManagers(), 
						 null);
		
				factory = ctx.getSocketFactory();
				  
				/*
				// Suites disponibles		
			
		    	 System.out.println ("*****************************************************");
		    	 System.out.println ("*         CypherSuites Disponibles en CLIENTE        ");
		    	 System.out.println ("*****************************************************");
		    	 
		         String[]cipherSuites = factory.getSupportedCipherSuites();
	 	   	     for (int i=0; i<cipherSuites.length; i++) 
	 	       		System.out.println (cipherSuites[i]);	    
	 		   	    
	 	   	     // Suites habilitadas por defecto
	 	   	     
		    	 System.out.println ("*****************************************************");
		    	 System.out.println ("*         CypherSuites Habilitadas por defecto       ");
		    	 System.out.println ("*****************************************************");
		     	    
	 	   	     String[] cipherSuitesDef = factory.getDefaultCipherSuites();
	 	   	     for (int i=0; i<cipherSuitesDef.length; i++) 
	 	       		 System.out.println (cipherSuitesDef[i]);*/
	     
			} catch (Exception e) {
					throw new IOException(e.getMessage());}

		  SSLSocket socket = (SSLSocket)factory.createSocket("localhost", 9001);
		 
		  // Ver los protocolos
		  /*
	  	  System.out.println ("*****************************************************");
	  	  System.out.println ("*  Protocolos soportados en Cliente                 ");
	  	  System.out.println ("*****************************************************");

		  String[] protocols = socket.getEnabledProtocols();
		  for (int i=0; i<protocols.length; i++) 
		    	System.out.println (protocols[i]);	    
	  		
	  	  System.out.println ("*****************************************************");
	  	  System.out.println ("*    Protocolo forzado                               ");
	  	  System.out.println ("*****************************************************");
		 	*/
		  String[] protocolsNew = {"TLSv1.3"};	  
		
		  socket.setEnabledProtocols(protocolsNew);

		  /*
		  System.out.println ("*****************************************************");
		  System.out.println ("*         CypherSuites  Disponibles (Factory)        ");
		  System.out.println ("*****************************************************");*/
	 
	      /*cipherSuitesDisponibles = factory.getSupportedCipherSuites();
	      for (int i=0; i<cipherSuitesDisponibles.length; i++) 
	 		  System.out.println (cipherSuitesDisponibles[i]);	    */
	      
	      // Habilitar las suites deseadas
	      
	      String[]   cipherSuitesHabilitadas = {//"TLS_RSA_WITH_NULL_SHA256",
	    		                               //"TLS_ECDHE_RSA_WITH_NULL_SHA",
								    		  "TLS_AES_128_GCM_SHA256",
								    		  //"TLS_AES_256_GCM_SHA384",
								    		  //"TLS_CHACHA20_POLY1305_SHA256",
								    		  //"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
								    		  //"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
								    		  //"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
								    		  //"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
								    		  //"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
								    		  //"TLS_RSA_WITH_AES_256_GCM_SHA384",
								    		  //"TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384",
								    		  //"TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384",
								    		  //"TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
								    		  //"TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
								    		  //"TLS_DHE_DSS_WITH_AES_256_GCM_SHA384",
								    		  //"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
								    		  //"TLS_RSA_WITH_AES_128_GCM_SHA256",
								    		  "TLS_RSA_WITH_AES_128_CBC_SHA256",
								    		  "TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384",
								    		  "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
								    		  "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
								    		  "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384",
								    		  "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
								    		  "TLS_RSA_WITH_AES_128_GCM_SHA256",
								    		  "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256",
								    		  "TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256",
								    		  "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256"
	  		  
	    		                               };	 
	     if (true)
	    	 socket.setEnabledCipherSuites(cipherSuitesHabilitadas);
	 	 /*
		 System.out.println ("*****************************************************");
		 System.out.println ("*         CypherSuites Habilitadas en socket         ");
		 System.out.println ("*****************************************************");
	     
	 	 String[] cipherSuitesHabilSocket = socket.getEnabledCipherSuites();
	  	 for (int i=0; i<cipherSuitesHabilSocket.length; i++) 
	 	       		System.out.println (cipherSuitesHabilSocket[i]);*/

	     socket.getSSLParameters().getUseCipherSuitesOrder();


		    /*
		     * send http request
		     *
		     * See SSLSocketClient.java for more information about why
		     * there is a forced handshake here when using PrintWriters.
		     */
		    
		    
		    System.out.println (" COMIENZO SSL HANDSHAKE");
		    System.out.println (" **********************");
		    socket.startHandshake();	    
		    System.out.println (" FIN SSL HANDSHAKE");
		    //String s = socket.getHandshakeSession().getCipherSuite();
		    System.out.println (" " + socket.getSession() +"");
		    
		    ////////////////////////////////////////////////////////////////////
			
		    try {
				OutputStream streamSalida;
				PrintWriter flujoCabecera;
				ObjectOutputStream flujoDatos;
				
				InputStream streamEntrada;
				BufferedReader    flujoCabecera_E;
				ObjectInputStream flujoDatos_E;
			   
				
				String inputLine = new String();
		    
	
			int salir = 0;
			while(salir==0) {
				String opcion = menu();
				
				switch(opcion.toUpperCase()) {
					case "R" : 
						System.out.println("\n ********** REGISTRAR UN DOCUMENTO **********\n");
						
						//Obtener el Certificado de Autenticación del cliente 
						X509Certificate certificadoAutenticacionCliente = (X509Certificate) ks.getCertificate("cliente_cert");
						byte[] certificadoAutClienteBytes = certificadoAutenticacionCliente.getEncoded();
						Principal idPropietario = certificadoAutenticacionCliente.getSubjectX500Principal();
						String id = "cliente";

						//Obterner nombre documento
						String nombreDocumento = "";
						do {
							System.out.print(" Introduce el nombre del documento [0-100]: ");
							nombreDocumento = keyboard.nextLine();
						} while(nombreDocumento.length()>100) ;
						
						byte[] docBytes = null; 
						docBytes = Crypto.getBytes(nombreDocumento); //Pasamos el documento a bytes
						
						/* CIFRADO PGP 
						 * 		Cifrado Simétrico del documento
						 * 		Cifrado Asimétrico de la clave
						 */
						
						// Generamos una clave aleatoria
						KeyGenerator kgen = KeyGenerator.getInstance(algoritmo);
						kgen.init(longclave);
						SecretKey skey = kgen.generateKey();
						
						byte[] skey_raw = skey.getEncoded(); //Pasamos a bytes
						SecretKeySpec keys = new SecretKeySpec(skey_raw, algoritmo);
						
						//CIFRADO SIMETRICO
						byte [] cifradoSimetricoDocumento = CifradoSimetrico.cifradoSimetrico(docBytes,keys);
						byte [] parametrosCifradoSimetrico = CifradoSimetrico.obtenerParametros();
						
						//CIFRADO ASIMETRICO DE LA CLAVE KS
						//Leer la clave publica del servidor del trustsotreclienteAplicacion
						PublicKey clavePublica = Crypto.getPublicKey("trustStoreAplicacion.jce","1234","servidor");
						
						byte [] cifradoAsimetricoClave = CifradoDescrifradoAsimetrico.cifradoAsimetrico(skey_raw,clavePublica);
						
						
						//FIRMA
						
						// Obtener la clave privada del keystore
						X509Certificate certificadoClienteFirma = (X509Certificate) ks.getCertificate("firma_cliente_cert");
						byte[] certificadoClienteFirmaBytes = certificadoClienteFirma.getEncoded();
						Principal idPropietarioFirma = certificadoAutenticacionCliente.getSubjectX500Principal();
						String idFirma = "firma_cliente";
						
				    	PrivateKey privateKey = Crypto.getPrivateKey(ks,idFirma,passwordKeyStore);
						byte[] firmaDocumento = FirmaAsimetricaKeyStore.firmaAsimetrica(docBytes, privateKey);
						
						
						//Guardamos en el mapa el documento y su firma hasta la respuesta del servidor
						archivosCliente.put(docBytes,firmaDocumento);
						
						MensajeRegistrar_Request mensajeRegistro = new MensajeRegistrar_Request(certificadoAutClienteBytes,nombreDocumento,
								cifradoAsimetricoClave,cifradoSimetricoDocumento,firmaDocumento,certificadoClienteFirmaBytes,parametrosCifradoSimetrico);

						streamSalida = socket.getOutputStream();
						flujoCabecera = new PrintWriter(new BufferedWriter(new OutputStreamWriter(streamSalida)));
						flujoDatos = new ObjectOutputStream(streamSalida);
						// enviar cabecera
						flujoCabecera.println("REGISTRAR");
						flujoCabecera.flush();
						// envíar  datos
						flujoDatos.writeObject(mensajeRegistro);
						flujoDatos.flush();
						
						/* ENVIAMOS MENSAJE REQUEST AL SERVIDOR */
							
						// Leer Respuesta 
						//Flujos entrantes para cabecera y datos  
						streamEntrada = socket.getInputStream();
						flujoCabecera_E = new BufferedReader(new InputStreamReader(streamEntrada));
						flujoDatos_E    = new ObjectInputStream(streamEntrada);
					   
					    //inputLine = flujoCabecera_E.readLine();
					    MensajaRegistrar_Response mensajeRespuesta = (MensajaRegistrar_Response) flujoDatos_E.readObject();
					    
					    double nerror = mensajeRespuesta.getNumeroError();
					    String error = Double.toString(nerror);
					    if(error.equals("0.0")==false) {
					    	switch(error) {
					    	case "-1.0" :
					    		System.out.println(" ERROR: CERTIFICADO DE FIRMA INCORRECTO");
					    		break;
					    	case "-2.0" :
					    		System.out.println(" ERROR: IDENTIDAD INCORRECTA");
					    		break;
					    	case "-3.0" :
					    		System.out.println(" ERROR: FIRMA INCORRECTA");
					    		break;
					    	}
					    }else {
					    	System.out.println(" RESPUESTA CORRECTA");
					    	byte[] certFirmaServidor = mensajeRespuesta.getCertificadoFirmas();
					    	
					    	//Comparamos con el certificado guardado en el trustsotre
					    	X509Certificate certificadoServidorFirma = (X509Certificate) ts.getCertificate("firma_servidor");
				        	byte[] certificadoServidorFirmaBytes = certificadoServidorFirma.getEncoded();
				        	if(Arrays.equals(certFirmaServidor, certificadoServidorFirmaBytes)){
				        		System.out.println(" CERTIFICADO DE REGISTRADOR CORRECTO");
				        		//Verificamos la firma
				        		PublicKey clavePublicaSer = Crypto.getPublicKey("trustStoreCliente.jce","1234","firma_servidor");
				        		
				        		/* FIRMA DEL SERVIDOR SIGRD */
				        		
				        		//Recuperar documento y firma guardada
				        		Set<Map.Entry<byte[], byte[]>> entrySet = archivosCliente.entrySet();
				                List<Map.Entry<byte[], byte[]> > entryList = new ArrayList<>(entrySet);
				                byte[] documentoGuardado = entryList.get(0).getKey();
				                byte[] firmaGuardada = entryList.get(0).getValue();
				                
				  	    	  	ByteArrayOutputStream firmaSigRD = new ByteArrayOutputStream();
				  	    	  	firmaSigRD.write(mensajeRespuesta.getIdRegistro());
				  	    	  	firmaSigRD.write(mensajeRespuesta.getIdPropietario());
				  	    	  	firmaSigRD.write(documentoGuardado);
				  	    	  	firmaSigRD.write(firmaGuardada);
				  	    	  	firmaSigRD.close();
				  	    	  	
				        		boolean verFirma = FirmaAsimetricaKeyStore.verificacionAsimetrica(firmaSigRD.toByteArray(),mensajeRespuesta.getFirmaRegistrador(),clavePublicaSer,certificadoServidorFirma);
				        		
				        		if(verFirma) {
						    		//Computar y almacenar el hash
						    		System.out.println(" Documento registrado correctamente con Id de Registro="+mensajeRespuesta.getIdRegistro());
						    		MessageDigest dig = MessageDigest.getInstance("SHA-256");
						    		byte[] hash = dig.digest(documentoGuardado);
						    		hashRespuestaServidor.put(mensajeRespuesta.getIdRegistro(), hash);
						    		//Borrar el documento enviado y la firma
						    		archivosCliente.remove(documentoGuardado);
						    		System.out.println(" Hash guardado correctamente");
						    	} else {
						    		System.out.println(" FIRMA INCORRECTA DEL REGISTRADOR");
						    	}
				        	}else {
				        		System.out.println(" CERTIFICADO DE REGISTRADOR INCORRECTO");
				        	}
					    }
					    					    						
						break;
						
					case "O" : 
						System.out.println("\n ********** RECUPERAR DOCUMENTO **********\n");
												
						//Obtener certificadoAutenticacionCliente 
						X509Certificate certificadoAutClienteRecuperar= (X509Certificate) ks.getCertificate("cliente_cert");
						byte[] certificadoAutClienteRecuperarBytes = certificadoAutClienteRecuperar.getEncoded();
						Principal idPropietarioRecuperar = certificadoAutClienteRecuperar.getSubjectX500Principal();
						String idRecuperar= idPropietarioRecuperar.getName(); 
						
						//Preguntamos por el iD Registro
						System.out.print(" INTRODUCE EL ID DE REGISTRO: ");
						int idDocumento = Integer.parseInt(keyboard.nextLine());
						
						//Creamos el objeto
						RecuperarDocumento_Request mensajeRecuperarRequest = new RecuperarDocumento_Request(certificadoAutClienteRecuperarBytes,idDocumento);

						
						streamSalida = socket.getOutputStream();
						flujoCabecera = new PrintWriter(new BufferedWriter(new OutputStreamWriter(streamSalida)));
						flujoDatos = new ObjectOutputStream(streamSalida);
						// enviar cabecera
						flujoCabecera.println("RECUPERAR");
						flujoCabecera.flush();
						// envíar  datos
						flujoDatos.writeObject(mensajeRecuperarRequest);
						flujoDatos.flush();
						
						// Leer Respuesta 
						streamEntrada = socket.getInputStream();
						flujoCabecera_E = new BufferedReader(new InputStreamReader(streamEntrada));
						flujoDatos_E    = new ObjectInputStream(streamEntrada);
					   
						RecuperarDocumento_Response respuestaRecuperar = (RecuperarDocumento_Response) flujoDatos_E.readObject();
	
				    
						double nerror2 = respuestaRecuperar.getNumeroError();
					    String error2 = Double.toString(nerror2);
					    if(error2.equals("0.0")==false) {
					    	switch(error2) {
					    	case "-1.0" :
					    		System.out.println(" ERROR: EL DOCUMENTO NO EXISTE");
					    		break;
					    	case "-2.0" :
					    		System.out.println(" ERROR: ACCESO NO PERMITIDO");
					    		break;
					    	}
					    }else {
					    	System.out.println(" RESPUESTA CORRECTA");
					    	byte[] certFirmaServidorBytes = respuestaRecuperar.getCertificadoFirmas();
					    	//Comparamos con el certificado guardado en el trustsotre
					    	X509Certificate certificadoServidorFirma = (X509Certificate) ts.getCertificate("firma_servidor");
				        	byte[] certificadoServidorFirmaBytes = certificadoServidorFirma.getEncoded();
				        	if(Arrays.equals(certFirmaServidorBytes, certificadoServidorFirmaBytes)){
				        		
				        		System.out.println(" CERTIFICADO DE REGISTRADOR CORRECTO");
				        		
				        		/* Descifrado PGP */
				        		//Para descifrado asimetrico sacamos la privada del keystore del cliente
					  	    	PrivateKey privateKeyRecuperar = Crypto.getPrivateKey(ks,"cliente",passwordKeyStore);
					  	    	byte[] claveKS = CifradoDescrifradoAsimetrico.descifradoAsimetrico(respuestaRecuperar.getcifradoClavePublica(),privateKeyRecuperar);
					  		    
					  	    	//Obtenemos la clave K para el descifrado simetrico
					  	    	SecretKeySpec keysRecuperar = new SecretKeySpec(claveKS,"AES");
					  	    	byte[] documentoDescifrado = CifradoSimetrico.descifradoSimetrico(respuestaRecuperar.getdocumentoCifrado(),keysRecuperar,respuestaRecuperar.getParametros());
					  	    	 
					  	    	//Sacamos la clave pública del certificado del servidor recibido
					  	    	InputStream inStream = new ByteArrayInputStream(certFirmaServidorBytes);
					  	    	CertificateFactory cf = CertificateFactory.getInstance("X.509");
					  	    	X509Certificate certFirmaServidor = (X509Certificate) cf.generateCertificate(inStream);
					  	    	PublicKey clavePublicaSer = certFirmaServidor.getPublicKey();
					  	    	
					  	    	//Firmamos el documento
					  	    	PrivateKey privateKeyRecuperarFirma = Crypto.getPrivateKey(ks,"firma_cliente",passwordKeyStore);
					  		    byte[] firmaRecuperar = FirmaAsimetricaKeyStore.firmaAsimetrica(documentoDescifrado, privateKeyRecuperarFirma);
					  	    	
					  		    /* FIRMA DEL SERVIDOR SIGRD */
				  	    	  	ByteArrayOutputStream firmaSigRD = new ByteArrayOutputStream();
				  	    	  	firmaSigRD.write(respuestaRecuperar.getIdRegistro());
				  	    	  	firmaSigRD.write(respuestaRecuperar.getIdPropietario());
				  	    	  	firmaSigRD.write(documentoDescifrado);
				  	    	  	firmaSigRD.write(firmaRecuperar);
				  	    	  	firmaSigRD.close();
				  	    	  	
				        		boolean verFirma = FirmaAsimetricaKeyStore.verificacionAsimetrica(firmaSigRD.toByteArray(),respuestaRecuperar.getFirmaRegistrador(),clavePublicaSer,certificadoServidorFirma);
				        		
				        		if(verFirma) {
						    		//Computar y almacenar el hash
						    		MessageDigest dig = MessageDigest.getInstance("SHA-256");
						    		byte[] hash = dig.digest(documentoDescifrado);
						    		
						    		byte[] hashGuardado = hashRespuestaServidor.get(respuestaRecuperar.getIdRegistro());
						    		if(Arrays.equals(hash,hashGuardado)) {
						    			System.out.println(" Documento recuperado correctamente con Id de Registro="+respuestaRecuperar.getIdRegistro());
						    			FileOutputStream salida = new FileOutputStream("./documentos/documento_"+respuestaRecuperar.getIdRegistro()+"_Recuperado.jpg");
						    			salida.write(documentoDescifrado);
						    			salida.close();
						    		}else {
						    			System.out.println(" DOCUMENTO MODIFICADO");
						    		}
						    		
						    		
						    	} else {
						    		System.out.println(" ERROR DE FIRMA DEL REGISTRADOR");
						    	}
				        	}else {
				        		System.out.println(" CERTIFICADO DE REGISTRADOR INCORRECTO");
				        	}
					    }
						
						break;
						
					case "X" :
						salir=1;
						break;	
						
				}
				
			}
		    } catch(Exception e) {
		    	System.out.println(e.getMessage());
		    }
			
		} catch(SocketException e) {
			System.out.println(" Socket Exception");
		} catch(IOException e1) {
			System.out.println(e1.getMessage());
		} catch(Exception e2) {
			System.out.println(" Excepcion genérica");
		}
		
		
	}
	
	static String menu() {
        System.out.println("\n________________________________________________\n");
        System.out.println(" Introduce el servicio al que quieres acceder: \n"
                    + "  [R] - Registrar un documento\n"
                    + "  [O] - Recuperar un documento\n"
                    + "  [X] - Salir del programa");
        System.out.println("\n________________________________________________\n");

		System.out.print(" Ha seleccionado: ");
		
		return (keyboard.nextLine());
		
	}
	
	static int menuOCSP() {
        System.out.println("\n________________________________________________\n");
        System.out.println(" Introduce el método OCSP que desea usar: \n"
                    + "  [1] - OCSP\n"
                    + "  [2] - OCSP Stapling\n"
                    + "  [3] - No usar revocación");
        System.out.println("\n________________________________________________\n");

		System.out.print(" Ha seleccionado: ");
		
		
		return (keyboardOCSP.nextInt());
		
	}
	
	private static void definirAlmacenesCliente(String keyStoreFile, String passwordKeyStore,String trustStoreFile)
	{
		String 	raizMios     = "/home/miguel/SEG/";

		// Almacen de claves
		
		System.setProperty("javax.net.ssl.keyStore",            raizMios + keyStoreFile);
		System.setProperty("javax.net.ssl.keyStoreType",       "JCEKS");
		System.setProperty("javax.net.ssl.keyStorePassword",   passwordKeyStore);

		// Almacen de confianza
		
		System.setProperty("javax.net.ssl.trustStore",          raizMios + trustStoreFile);		
		System.setProperty("javax.net.ssl.trustStoreType",     "JCEKS");
		System.setProperty("javax.net.ssl.trustStorePassword", "1234");

	}
    
    private static void definirRevocacionOCSP()
	{

		// Almacen de claves
		
		System.setProperty("com.sun.net.ssl.checkRevocation",        "true");
		System.setProperty("ocsp.enable",                            "true");

	}
    
    private static void definirRevocacionOCSPStapling()
	{

		// Almacen de claves
		
		System.setProperty("jdk.tls.client.enableStatusRequestExtension",   "true");
		System.setProperty("com.sun.net.ssl.checkRevocation",        "true");
		System.setProperty("ocsp.enable",                            "false");
		System.getProperty("jdk.tls.client.enableStatusRequestExtension");

	}
		
}
