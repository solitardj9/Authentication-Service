package com.solitardj9.authService.application.thingCertMngt.service.impl;

import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.sql.Date;
import java.time.LocalDate;

import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.solitardj9.authService.application.caCertMngt.model.CaCertificate;
import com.solitardj9.authService.application.caCertMngt.service.CaCertManager;
import com.solitardj9.authService.application.thingCertMngt.model.ThingCertificate;
import com.solitardj9.authService.application.thingCertMngt.service.ThingCertManager;
import com.solitardj9.authService.utils.security.CertificateInfo;
import com.solitardj9.authService.utils.security.CertificateUtil;

@Service("thingCertManager")
public class ThingCertManagerImpl implements ThingCertManager {
	//
	private static final Logger logger = LoggerFactory.getLogger(ThingCertManagerImpl.class);
	
	@Autowired
	CaCertManager caCertManager;
	
	@Value("${thing.certificate.duration}")
	private Long duration;
	
	@Value("${thing.certificate.signatureAlgorithm}")
	private String signatureAlgorithm;
	
	@Override
	public ThingCertificate createThingCertificate(String csr) {
		//
		// 1) CSR 생성
		PKCS10CertificationRequest pkcs10CertificationRequest = CertificateUtil.readPKCS10CertificationRequest(csr);
		
		if (pkcs10CertificationRequest == null) {
			logger.error("pkcs10CertificationRequest is null.");
			return null;
		}	

		// 2) create Certificate
		try {
			CaCertificate caCertificate = caCertManager.getCaCertificate();
			X509Certificate x509Certificate = createCertificate(pkcs10CertificationRequest, caCertificate);
			
			ThingCertificate thingCertificate = new ThingCertificate(x509Certificate);
			return thingCertificate;
		} catch (Exception e) {
			logger.error(e.toString());
			return null;
		}		
	}
	
	private X509Certificate createCertificate(PKCS10CertificationRequest pkcs10CertificationRequest, CaCertificate caCertificate) {
		//
		// 1) extract Certificate and Private Key
		X509Certificate certificate = caCertificate.getCaCertificate();
		PrivateKey privateKey = caCertificate.getPrivateKey();
		
		// 2) create Thing Certificate Info and check validation 
		CertificateInfo certificateInfo = new CertificateInfo(duration, BigInteger.valueOf((int)new SecureRandom().nextInt()), KeyUsage.digitalSignature, false);

		if (!checkCertificateInfo(certificateInfo)) {
			logger.error("certificateInfo is not valid.");
			return null;
		}	
		
		// 3) create Expired Date
		LocalDate now = LocalDate.now();
		Date createdDate = Date.valueOf(now);															// start of validity
		Date expiredDate = Date.valueOf(now.plusYears(certificateInfo.getValidDuration()));		// end of validity
		
		// 4) create Thing Certificate
		X509Certificate x509Certificate = CertificateUtil.generateX509Certificate(certificateInfo, certificate, privateKey, pkcs10CertificationRequest, createdDate, expiredDate, signatureAlgorithm);
		
		return x509Certificate;
	}
	
	private boolean checkCertificateInfo(CertificateInfo certificateInfo) {
		//
		if(certificateInfo.getKeyUsage() != KeyUsage.digitalSignature) {
			logger.error("keyUsage is wrong!");
			certificateInfo.setKeyUsage(KeyUsage.keyCertSign);
			return false;
		}
		
		if(certificateInfo.getBasicConstratints()) {
			logger.error("BasicConstratint must be true!");
			certificateInfo.setBasicConstratints(false);
			return false;
		}
		
		if(certificateInfo.getValidDuration() < 0 ) {
			logger.error("ValidDuration is wrong!");
			return false;
		}
		
		return true;
	}
}