package Mensajes;

import java.io.*;

import javax.crypto.spec.SecretKeySpec;

public class MensajeRegistrar_Request implements Serializable{

	private static final long serialVersionUID = 3767187860478482711L;

	private String nombreDoc;
	private byte[] documentoCifrado;
	private byte[] cifradoClavePublica;
	private byte[] parametrosCifrado; //paremtros de cifrado
	private byte[] firmaDocumento;
	private byte[] certificadoFirmaC;
	private byte[] certificadoAutenticacionCliente;
	
	public MensajeRegistrar_Request () {
		
	}
	
	
	public MensajeRegistrar_Request (byte[] certificadoAutenticacionCliente, String nombreDoc,byte[]cifradoClavePublica, 
			byte[] documentoCifrado, byte[] firmaDocumento, byte[] certificadoFirmaC, byte[] parametrosCifrado)  {
		
		this.certificadoAutenticacionCliente = certificadoAutenticacionCliente;
		this.nombreDoc = nombreDoc;
		this.documentoCifrado = documentoCifrado;
		this.firmaDocumento = firmaDocumento;
		this.certificadoFirmaC = certificadoFirmaC;
		this.cifradoClavePublica = cifradoClavePublica;
		this.parametrosCifrado = parametrosCifrado;
	
	}
	
	public static MensajeRegistrar_Request request() {
		MensajeRegistrar_Request objeto = new MensajeRegistrar_Request();
		return objeto;
		
	}
	
	public String getNombreDoc() {
		return nombreDoc;
	}

	public void setNombreDoc(String nombreDoc) {
		this.nombreDoc = nombreDoc;
	}

	public byte[] getDocumentoCifrado() {
		return documentoCifrado;
	}

	public void setDocumentoCifrado(byte[] documentoCifrado) {
		this.documentoCifrado = documentoCifrado;
	}

	public byte[] getClavePublica() {
		return cifradoClavePublica;
	}

	public void setClavePublica(byte[] clavePublica) {
		this.cifradoClavePublica = clavePublica;
	}

	public byte[] getParametrosCifrado() {
		return parametrosCifrado;
	}

	public void setParametrosCifrado(byte[] parametrosCifrado) {
		this.parametrosCifrado = parametrosCifrado;
	}

	public byte[] getFirmaDocumento() {
		return firmaDocumento;
	}

	public void setFirmaDocumento(byte[] firmaDocumento) {
		this.firmaDocumento = firmaDocumento;
	}

	public byte[] getCertificadoFirmaC() {
		return certificadoFirmaC;
	}

	public void setCertificadoFirmaC(byte[] certificadoFirmaC) {
		this.certificadoFirmaC = certificadoFirmaC;
	}

	public byte[] getCertificadoAutenticacionCliente() {
		return certificadoAutenticacionCliente;
	}

	public void setCertificadoAutenticacionCliente(byte[] certificadoAutenticacionCliente) {
		this.certificadoAutenticacionCliente = certificadoAutenticacionCliente;
	}

}
