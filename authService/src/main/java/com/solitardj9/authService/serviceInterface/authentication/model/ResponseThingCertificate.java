package com.solitardj9.authService.serviceInterface.authentication.model;

public class ResponseThingCertificate {
	//
	private String certificatePem;
	
	public ResponseThingCertificate(String certificatePem) {
		this.certificatePem = certificatePem;
	}

	public String getCertificatePem() {
		return certificatePem;
	}

	public void setCertificatePem(String certificatePem) {
		this.certificatePem = certificatePem;
	}
}