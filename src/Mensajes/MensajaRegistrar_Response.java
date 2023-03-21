package Mensajes;

import java.io.*;

public class MensajaRegistrar_Response implements Serializable{

	private static final long serialVersionUID = -9065170867036496728L;
	
	private double numeroError;
	private int idRegistro;
	private byte[] idPropietario;
	private byte[] firmaRegistrador;
	private byte[] certificadoFirmas;
	
	public MensajaRegistrar_Response () {
		
	}
	
	public MensajaRegistrar_Response (double numeroError) {
		this.numeroError = numeroError;
	}
	
	public MensajaRegistrar_Response (double numeroError, int idRegistro, byte[] idPropietario, byte[] firmaRegistrador, byte[] certificadoFirmas ) {
		this.numeroError = numeroError;
		this.idRegistro = idRegistro;
		this.idPropietario = idPropietario;
		this.firmaRegistrador = firmaRegistrador;
		this.certificadoFirmas = certificadoFirmas;
	}
	
	public static void response(MensajaRegistrar_Response objeto) {
		/*lo que tengamos que hacer*/
		
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
}
