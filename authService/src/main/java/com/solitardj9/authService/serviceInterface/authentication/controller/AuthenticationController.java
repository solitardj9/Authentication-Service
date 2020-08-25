package com.solitardj9.authService.serviceInterface.authentication.controller;

import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.solitardj9.authService.application.caCertMngt.service.CaCertManager;
import com.solitardj9.authService.application.thingCertMngt.model.ThingCertificate;
import com.solitardj9.authService.application.thingCertMngt.service.ThingCertManager;
import com.solitardj9.authService.serviceInterface.authentication.model.ResponseThingCertificate;
import com.solitardj9.authService.serviceInterface.common.StatusCode;
import com.solitardj9.authService.utils.security.CertificateUtil;

@RestController
public class AuthenticationController {

	@Autowired
	ThingCertManager thingCertManager;
	
	@Autowired
	CaCertManager caCertManager;
	
	/**
	 * @param requestMap
	 * {
	 * 		"csr" : "{PEM String}"
	 * }
	 * 
	 * @return
	 */
	@SuppressWarnings({ "rawtypes", "unchecked" })
	@PostMapping("/certificate")
	public ResponseEntity createCertificateFromCsr(@RequestBody Map<String, String> requestMap) {
		//
		ResponseThingCertificate response = null;
		
		String csr = requestMap.get("csr");
		
		if (csr == null || csr.isEmpty()) {
			return new ResponseEntity(StatusCode.Invalid_Request.getMessage(), StatusCode.Invalid_Request.getHttpStatus());
		}
		
		ThingCertificate thingCertificate = null;
		try {
			thingCertificate = thingCertManager.createThingCertificate(csr);
			
			if (thingCertificate == null) {
				return new ResponseEntity(StatusCode.INTERNAL_SERVER_ERROR.getMessage() , HttpStatus.INTERNAL_SERVER_ERROR);
			}
			
			response = new ResponseThingCertificate(CertificateUtil.makeX509CertificateAsPem(thingCertificate.getCaCertificate()));
			return new ResponseEntity(response , HttpStatus.OK);
		} catch (Exception e) {
			return new ResponseEntity(StatusCode.INTERNAL_SERVER_ERROR.getMessage(), StatusCode.INTERNAL_SERVER_ERROR.getHttpStatus());
		}
	}
	
	/**
	 * @param requestMap
	 * {
	 * 		"cert" : "{PEM String}",
	 *      "pvKey" : "{PEM String}"
	 * }
	 * 
	 * @return
	 */
	@SuppressWarnings({ "rawtypes", "unchecked" })
	@PostMapping("/ca")
	public ResponseEntity registerCa(@RequestBody Map<String, String> requestMap) {
		//
		String strCaCertificate = requestMap.get("caCert");
		String strPrivateKey = requestMap.get("pvKey");
		
		if (strCaCertificate == null || strCaCertificate.isEmpty()) {
			return new ResponseEntity(StatusCode.Invalid_Request.getMessage(), StatusCode.Invalid_Request.getHttpStatus());
		}
		
		if (strPrivateKey == null || strPrivateKey.isEmpty()) {
			return new ResponseEntity(StatusCode.Invalid_Request.getMessage(), StatusCode.Invalid_Request.getHttpStatus());
		}
		
		try {
			Boolean response = caCertManager.updateCaCertificateWithPEM(strCaCertificate, strPrivateKey);
			
			if (response == false) {
				return new ResponseEntity(StatusCode.INTERNAL_SERVER_ERROR.getMessage() , HttpStatus.INTERNAL_SERVER_ERROR);
			}
			
			return new ResponseEntity(response , HttpStatus.OK);
		} catch (Exception e) {
			return new ResponseEntity(StatusCode.INTERNAL_SERVER_ERROR.getMessage(), StatusCode.INTERNAL_SERVER_ERROR.getHttpStatus());
		}
	}
}