package com.solitardj9.authService.application.caCertMngt.model;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

public class CaCertificate {	
    //
	private PrivateKey privateKey;
	
	private X509Certificate caCertificate;
	
	public CaCertificate() {
	}
	
	public CaCertificate(PrivateKey privateKey, X509Certificate caCertificate) {
	    //
		this.privateKey = privateKey;
		this.caCertificate = caCertificate;
	}

	public PrivateKey getPrivateKey() {
		return privateKey;
	}

	public void setPrivateKey(PrivateKey privateKey) {
		this.privateKey = privateKey;
	}

	public X509Certificate getCaCertificate() {
		return caCertificate;
	}

	public void setCaCertificate(X509Certificate caCertificate) {
		this.caCertificate = caCertificate;
	}
	
	@Override
	public String toString() {
		return "CaCertificate [privateKey=" + privateKey + ", caCertificate=" + caCertificate + "]";
    }
}