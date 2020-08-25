package com.solitardj9.authService.application.thingCertMngt.model;

import java.security.cert.X509Certificate;

public class ThingCertificate {	
    //
	private X509Certificate caCertificate;
	
	public ThingCertificate() {
	}
	
	public ThingCertificate(X509Certificate caCertificate) {
	    //
		this.caCertificate = caCertificate;
	}

	public X509Certificate getCaCertificate() {
		return caCertificate;
	}

	public void setCaCertificate(X509Certificate caCertificate) {
		this.caCertificate = caCertificate;
	}

	@Override
	public String toString() {
		return "ThingCertificate [caCertificate=" + caCertificate + "]";
	}
}