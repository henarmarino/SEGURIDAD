package Mensajes;

import java.io.*;

public class RecuperarDocumento_Request implements Serializable {

	private static final long serialVersionUID = -4391446410389706623L;
	

	private byte[] certificadoAutenticacionCliente;
	private int idRegistro;
	
	public RecuperarDocumento_Request() {
		
	}
	
	public RecuperarDocumento_Request(byte[] certificadoAutenticacionCliente, int idRegistro) {
		this.certificadoAutenticacionCliente = certificadoAutenticacionCliente;
		this.idRegistro = idRegistro;
	}

	public byte[] getCertificadoAutenticacionCliente() {
		return certificadoAutenticacionCliente;
	}

	public void setCertificadoAutenticacionCliente(byte[] certificadoAutenticacionCliente) {
		this.certificadoAutenticacionCliente = certificadoAutenticacionCliente;
	}

	public int getIdRegistro() {
		return idRegistro;
	}

	public void setIdRegistro(int idRegistro) {
		this.idRegistro = idRegistro;
	}
}
