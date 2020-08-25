package com.solitardj9.authService.application.caCertMngt.service;

import com.solitardj9.authService.application.caCertMngt.model.CaCertificate;

public interface CaCertManager {
    //
	public CaCertificate getCaCertificate();
	
	public Boolean updateCaCertificateWithPEM(String strCaCertificate, String strPrivateKey);
}