package com.solitardj9.authService.application.caCertMngt.model;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

public class CaCertificate {	
    //
	private X509Certificate caCertificate;
	
	private PublicKey publicKey;
	
	private PrivateKey privateKey;
	
	public CaCertificate() {
	}

	public CaCertificate(X509Certificate caCertificate, PublicKey publicKey, PrivateKey privateKey) {
		this.caCertificate = caCertificate;
		this.publicKey = publicKey;
		this.privateKey = privateKey;
	}

	public X509Certificate getCaCertificate() {
		return caCertificate;
	}

	public void setCaCertificate(X509Certificate caCertificate) {
		this.caCertificate = caCertificate;
	}

	public PublicKey getPublicKey() {
		return publicKey;
	}

	public void setPublicKey(PublicKey publicKey) {
		this.publicKey = publicKey;
	}

	public PrivateKey getPrivateKey() {
		return privateKey;
	}

	public void setPrivateKey(PrivateKey privateKey) {
		this.privateKey = privateKey;
	}

	@Override
	public String toString() {
		return "CaCertificate [caCertificate=" + caCertificate + ", publicKey=" + publicKey + ", privateKey="
				+ privateKey + "]";
	}
}