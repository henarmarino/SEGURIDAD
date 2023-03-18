package Mensajes;

import java.io.*;

public class RecuperarDocumento_Response implements Serializable{

	private static final long serialVersionUID = 5900273719816677140L;
	
	private double numeroError;
	private int idRegistro;
	private byte[] idPropietario;
	private byte[] firmaRegistrador;
	private byte[] certificadoFirmas;
	private byte[] cifradoClavePublica;
	private byte[] parametros;
	private byte[] documentoCifrado;
	
	public RecuperarDocumento_Response () {
		
	}
	
	public RecuperarDocumento_Response (double numeroError) {
		this.numeroError = numeroError;
	}
	
	public RecuperarDocumento_Response (double numeroError, int idRegistro, byte[] idPropietario, byte[] cifradoClavePublica, 
			byte[] documentoCifrado,byte[] firmaRegistrador, byte[] parametros, byte[] certificadoFirmas ) {
		this.numeroError = numeroError;
		this.idRegistro = idRegistro;
		this.idPropietario = idPropietario;
		this.firmaRegistrador = firmaRegistrador;
		this.certificadoFirmas = certificadoFirmas;
		this.cifradoClavePublica = cifradoClavePublica;
		this.parametros = parametros;
		this.documentoCifrado = documentoCifrado;
	}
	
	public double getNumeroError() {
		return numeroError;
	}

	public void setNumeroError(double numeroError) {
		this.numeroError = numeroError;
	}

	public int getIdRegistro() {
		return idRegistro;
	}

	public void setIdRegistro(int idRegistro) {
		this.idRegistro = idRegistro;
	}

	public byte[] getIdPropietario() {
		return idPropietario;
	}

	public void setIdPropietario(byte[] idPropietario) {
		this.idPropietario = idPropietario;
	}

	public byte[] getFirmaRegistrador() {
		return firmaRegistrador;
	}

	public void setFirmaRegistrador(byte[] firmaRegistrador) {
		this.firmaRegistrador = firmaRegistrador;
	}

	public byte[] getCertificadoFirmas() {
		return certificadoFirmas;
	}

	public void setCertificadoFirmas(byte[] certificadoFirmas) {
		this.certificadoFirmas = certificadoFirmas;
	}

	public byte[] getcifradoClavePublica() {
		return cifradoClavePublica;
	}

	public void setcifradoClavePublica(byte[] cifradoClavePublica) {
		this.cifradoClavePublica = cifradoClavePublica;
	}

	public byte[] getdocumentoCifrado() {
		return documentoCifrado;
	}

	public void setdocumentoCifrado(byte[] documentoCifrado) {
		this.documentoCifrado = documentoCifrado;
	}

	public byte[] getParametros() {
		return parametros;
	}

	public void setParametros(byte[] parametros) {
		this.parametros = parametros;
	}
	
}
