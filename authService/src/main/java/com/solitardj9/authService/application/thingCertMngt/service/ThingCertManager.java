package com.solitardj9.authService.application.thingCertMngt.service;

import com.solitardj9.authService.application.thingCertMngt.model.ThingCertificate;

public interface ThingCertManager {
	
	public ThingCertificate createThingCertificate(String csr);
}