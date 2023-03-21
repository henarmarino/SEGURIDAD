package Principal;


import java.io.*;
import java.net.*;
import java.security.KeyStore;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.TreeMap;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.x500.X500Principal;

import Mensajes.*;
import Cifrar_Descifrar.*;


/************************************************************
 * ClassServer.java -- a simple file server that can serve
 * Http get request in both clear and secure channel
 *
 *  Basado en ClassServer.java del tutorial/rmi
 ************************************************************/
public abstract class ClassServer implements Runnable {

    private ServerSocket server = null;
    private static KeyStore ks;
	private static KeyStore ts;
	private static OutputStream streamSalida;
	private static PrintWriter flujoCabecera;
	private static ObjectOutputStream flujoDatos;
	private static String path = "./documentosServidor/";
	private static int idRegistro = 0;
	public static String algoritmo = "AES";
	public static int longclave = 192;
	private static TreeMap<Integer,ArrayList<byte[]>> documentosServidor = new TreeMap<Integer,ArrayList<byte[]>>();
	private static TreeMap<Integer,String> idPropietariosGuardados = new TreeMap<Integer,String>();

    /**
     * Constructs a ClassServer based on <b>ss</b> and
     * obtains a file's bytecodes using the method <b>getBytes</b>.
     *
     */
    protected ClassServer(ServerSocket ss,KeyStore keyStoreServer, KeyStore trustStoreServer)
    {
    		server = ss;
    		ks = keyStoreServer;
    		ts = trustStoreServer;
    		newListener();
    }

    /***************************************************************
     * run() -- The "listen" thread that accepts a connection to the
     * server, parses the header to obtain the file name
     * and sends back the bytes for the file (or error
     * if the file is not found or the response was malformed).
     **************************************************************/
    public void run()
    {
		Socket socket;
	
		// accept a connection

		try 
		{
		    socket = server.accept();
		    System.out.println("\n NUEVO CLIENTE\n");
	
		} 
		catch (IOException e) {
		    System.out.println(" Class Server died: " + e.getMessage());
		    e.printStackTrace();
		    return;
		}
	
		// create a new thread to accept the next connection
		newListener();

		try 
		{		    
		    while(socket.isConnected()) {
		    
				InputStream streamEntrada = socket.getInputStream();
				BufferedReader    flujoCabecera_E = new BufferedReader(new InputStreamReader(streamEntrada));
				ObjectInputStream flujoDatos_E    = new ObjectInputStream(streamEntrada);

				
				String accion = flujoCabecera_E.readLine(); //REGISTRAR
				if(accion.equals("REGISTRAR")) {
					System.out.println(" Vamos a intentar registrar");
					MensajeRegistrar_Request mensajeRegistrar = (MensajeRegistrar_Request) flujoDatos_E.readObject(); //OBJETO
					registrar(mensajeRegistrar,socket);
				}else if(accion.equals("RECUPERAR")){
					RecuperarDocumento_Request mensajeRecuperar = (RecuperarDocumento_Request) flujoDatos_E.readObject(); //OBJETO
					recuperar(mensajeRecuperar,socket);
				}
			    }
				    
	
		} catch (Exception ex) {
			System.out.println("\n UN CLIENTE SE HA DESCONECTADO\n");
	
		} finally {
		    try {
			socket.close();
		    } catch (IOException e) {
		    }
		}
    }

    /********************************************************
     * newListener()
     * 			Create a new thread to listen.
     *******************************************************/
    private void newListener()
    {
    	(new Thread(this)).start();
    }
      
      private static void registrar(MensajeRegistrar_Request Request, Socket socket) throws Exception, Exception {
    	  
    	  System.out.println("\n ********** REGISTRANDO DOCUMENTO **********\n");
    	  boolean certFirma = false;
    	  String idPropietario = "";
    	  double nerror=0;
    	  byte SigRD[] = null;
    	  byte certificadoFirmaServidorBytes[] = null;
    	  X509Certificate certificadoClienteFirma = null;
    	  
    	  /* VALIDAR CERTIFICADO DE FIRMA */
    	  for(int i=1;i<=3;i++) {
    		  certificadoClienteFirma = (X509Certificate) ts.getCertificate("firma_cliente"+i);
    		  //certificadoClienteFirma = (X509Certificate) ts.getCertificate("firma_cliente1");
        	  byte[] certificadoClienteFirmaBytes = certificadoClienteFirma.getEncoded();
        	  if(Arrays.equals(certificadoClienteFirmaBytes, Request.getCertificadoFirmaC())){
        		  System.out.println(" CERTIFICADO DE FIRMA CORRECTO");
        		  String idFirma = certificadoClienteFirma.getSubjectX500Principal().getName();
        		  certFirma = true;
        		  //Comprobamos las identidades
        		  byte[] certificadoAutenticacionClienteBytes = Request.getCertificadoAutenticacionCliente();
        		  InputStream inStream = new ByteArrayInputStream(certificadoAutenticacionClienteBytes);
        		  CertificateFactory cf = CertificateFactory.getInstance("X.509");
        		  X509Certificate certificadoAutenticacionCliente = (X509Certificate) cf.generateCertificate(inStream);
        		  String idCliente = certificadoAutenticacionCliente.getSubjectX500Principal().getName();
        		  String[] partes = idCliente.split("[,=]");
        		  idPropietario = partes[1];
        		  
        		  if(idFirma.contains(idPropietario)) {
        			  System.out.println(" IDENTIDAD CORRECTA");
        		  }else {
        			  System.out.println(" IDENTIDAD INCORRECTA");
        			  nerror=-2;
        		  }
        		  
        		  break;
        	  }
    	  }
    	  if(!certFirma) {
    		  System.out.println(" CERTIFICADO DE FIRMA INCORRECTO");
    		  nerror=-1;
    	  }
    	  if(nerror==0) {
	    		  
	    	  /* DESCIFRADO PGP */
	    	  //Para descifrado asimetrico sacamos la privada del keystore del servidor
	    	  PrivateKey privateKey = Crypto.getPrivateKey(ks,"keystoreservidor","1234");
		      byte[] claveKS = CifradoDescrifradoAsimetrico.descifradoAsimetrico(Request.getClavePublica(),privateKey);
		       
		      //Obtenemos la clave K para el descifrado simetrico
	    	  SecretKeySpec keys = new SecretKeySpec(claveKS,"AES");
	    	  byte[] documentoDescifrado = CifradoSimetrico.descifradoSimetrico(Request.getDocumentoCifrado(),keys,Request.getParametrosCifrado());
	    	   
	    	  /* VERIFICAR FIRMA DEL DOCUMENTO */
	    	  PublicKey clavePublica = ts.getCertificate("firma_"+idPropietario).getPublicKey();
	    	  boolean verFirma = FirmaAsimetricaKeyStore.verificacionAsimetrica(documentoDescifrado, Request.getFirmaDocumento(), clavePublica, certificadoClienteFirma);
	    	  if(!verFirma) {
	    		  nerror=-3;
	    	  }
	    	  
	    	  /* Ciframos el documento */
	    	  SecretKeySpec claveSecreta = Crypto.getClaveSecretaKeyStore(ks,"clavedes","1234");
	    	  byte[] documentoCifradoServidor = CifradoSimetrico.cifradoSimetricoServidor(documentoDescifrado, claveSecreta);
	    	  byte[] parametrosServidor = CifradoSimetrico.obtenerParametrosServidor();
	    	  ArrayList<byte[]> cifradoServidor = new ArrayList<byte[]>();
	    	  cifradoServidor.add(documentoCifradoServidor);
	    	  cifradoServidor.add(parametrosServidor);
	    	  
	    	  /* Guardar documento */
	    	  idRegistro++;
	    	  idPropietariosGuardados.put(idRegistro,idPropietario);
	    	  documentosServidor.put(idRegistro, cifradoServidor);
	    	  
	    	  /* FIRMA DEL SERVIDOR SIGRD */
	    	  ByteArrayOutputStream firmaServidor = new ByteArrayOutputStream();
	    	  firmaServidor.write(idRegistro);
	    	  firmaServidor.write(idPropietario.getBytes());
	    	  firmaServidor.write(documentoDescifrado);
	    	  firmaServidor.write(Request.getFirmaDocumento());
	    	  
	    	  //Sacamos la clave privada de firma del servidor
	    	  PrivateKey privateKeyFirma = Crypto.getPrivateKey(ks,"firma_servidor","1234");
	    	  SigRD = FirmaAsimetricaKeyStore.firmaAsimetrica(firmaServidor.toByteArray(), privateKeyFirma);
	    	  cifradoServidor.add(SigRD);
	    	  firmaServidor.close();
	    	  
	    	  /*Obtenemos el certificado de firma del servidor */
	    	  X509Certificate certificadoFirmaServidor = (X509Certificate) ks.getCertificate("firma_servidor_cert");
	    	  certificadoFirmaServidorBytes = certificadoFirmaServidor.getEncoded();
	    	  cifradoServidor.add(certificadoFirmaServidorBytes);
	
	    	  /* GUARDAR FICHERO */
	    	  FileOutputStream fichero = new FileOutputStream(path+idRegistro+"_"+idPropietario+".sig.cif");//idRegistro_idPropietario.sig.cif 
	    	  fichero.write(documentoCifradoServidor);
	    	  fichero.write(Request.getFirmaDocumento());
	    	  fichero.write(idRegistro);
	    	  fichero.write(SigRD);
	    	  fichero.close();
	    	  
    	  }
    	  
    	  /* ENVIAMOS RESPUESTA AL CLIENTE */
		  streamSalida = socket.getOutputStream();
		  flujoCabecera = new PrintWriter(new BufferedWriter(new OutputStreamWriter(streamSalida)));
		  flujoDatos = new ObjectOutputStream(streamSalida);
		  MensajaRegistrar_Response respuesta = new MensajaRegistrar_Response();
    	  
		  if(nerror!=0) {
			  respuesta = new MensajaRegistrar_Response(nerror);
		  }else {
			  respuesta = new MensajaRegistrar_Response(0,idRegistro,idPropietario.getBytes(),SigRD,certificadoFirmaServidorBytes);
		  }
    	  
    	  flujoDatos.writeObject(respuesta);
		  flujoDatos.flush();
      }
      
      private static void recuperar(RecuperarDocumento_Request recuperar,Socket socket) throws Exception {
    	  String idPropietario = "";
    	  int idRegistro = recuperar.getIdRegistro();
    	  double nerror = 0;
    	  byte[] documentoCifrado = null;
		  byte[] parametrosCifrado = null;
		  byte[] SigRD = null;
		  byte[] certFirmaServidor = null;
		  byte[] cifradoSimetricoDocumento = null;
		  byte[] cifradoAsimetricoClave = null;
		  byte[] parametrosCifradoSimetrico = null;

		  System.out.println("\n ********** RECUPERANDO DOCUMENTO **********\n");
		  
    	  //Comprobar si existe el documento
    	  if(idPropietariosGuardados.containsKey(idRegistro)){
    		  System.out.println(" EL DOCUMENTO EXISTE");
    		  //Comprobamos las identidades
    		  byte[] certificadoAutenticacionClienteBytes = recuperar.getCertificadoAutenticacionCliente();
    		  InputStream inStream = new ByteArrayInputStream(certificadoAutenticacionClienteBytes);
    		  CertificateFactory cf = CertificateFactory.getInstance("X.509");
    		  X509Certificate certificadoAutenticacionCliente = (X509Certificate) cf.generateCertificate(inStream);
    		  String idCliente = certificadoAutenticacionCliente.getSubjectX500Principal().getName();
    		  String[] partes = idCliente.split("[,=]");
    		  idPropietario = partes[1];
    		  if(idPropietariosGuardados.containsKey(idRegistro)) {
    			  String propietarioDocumento = idPropietariosGuardados.get(idRegistro);
    			  if(idPropietario.equals(propietarioDocumento)==false) {
    				  System.out.println(" ACCESO NO PERMITIDO");
    				  nerror=-2;
    			  }else {
    				  //Obtenemos el documento cifrado
				
    				  ArrayList<byte[]> cifradoServidor = documentosServidor.get(idRegistro);
    				  documentoCifrado = cifradoServidor.get(0);
    				  parametrosCifrado = cifradoServidor.get(1);
    				  SigRD = cifradoServidor.get(2);
    				  certFirmaServidor = cifradoServidor.get(3);
    				  
    				  SecretKeySpec claveSecreta2 = Crypto.getClaveSecretaKeyStore(ks,"clavedes","1234");
    				  byte[] documentoDescifradoServidor = CifradoSimetrico.descifradoSimetricoServidor(documentoCifrado, claveSecreta2, parametrosCifrado);
    				  
    				  // Generamos una clave aleatoria
    				  
    				  KeyGenerator kgen = KeyGenerator.getInstance(algoritmo);
    				  kgen.init(longclave);
    				  SecretKey skey = kgen.generateKey();
    				  
    				  byte[] skey_raw = skey.getEncoded(); //Pasamos a bytes
    				  SecretKeySpec keys = new SecretKeySpec(skey_raw, algoritmo);
    				  
    				  //CIFRADO SIMETRICO
    				  cifradoSimetricoDocumento = CifradoSimetrico.cifradoSimetrico(documentoDescifradoServidor,keys);
    				  parametrosCifradoSimetrico = CifradoSimetrico.obtenerParametros();
    				  
    				  //CIFRADO ASIMETRICO DE LA CLAVE KS
    				  //Leer la clave publica del servidor del certificado de autenticacion del cliente
    				  PublicKey publicKey = certificadoAutenticacionCliente.getPublicKey();
    				  cifradoAsimetricoClave = CifradoDescrifradoAsimetrico.cifradoAsimetrico(skey_raw,publicKey);
						
    			  }
    		  }
    		  
    	  } else {
    		  System.out.println(" EL DOCUMENTO NO EXISTE");
    		  nerror = -1;
    	  }
    	  
    	  streamSalida = socket.getOutputStream();
		  flujoCabecera = new PrintWriter(new BufferedWriter(new OutputStreamWriter(streamSalida)));
		  flujoDatos = new ObjectOutputStream(streamSalida);
		  RecuperarDocumento_Response respuesta = new RecuperarDocumento_Response();
    	  

		  if(nerror!=0) {
			  respuesta = new RecuperarDocumento_Response(nerror);
		  }else {
			  respuesta = new RecuperarDocumento_Response(0,idRegistro,idPropietario.getBytes(),cifradoAsimetricoClave,cifradoSimetricoDocumento,SigRD,parametrosCifradoSimetrico,certFirmaServidor);
		  }
    	  
    	  flujoDatos.writeObject(respuesta);
		  flujoDatos.flush();
      }
}
