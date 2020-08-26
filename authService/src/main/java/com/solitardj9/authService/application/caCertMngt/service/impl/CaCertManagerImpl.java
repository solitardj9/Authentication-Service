package com.solitardj9.authService.application.caCertMngt.service.impl;

import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.sql.Date;
import java.time.LocalDate;

import javax.annotation.PostConstruct;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.solitardj9.authService.application.caCertMngt.model.CaCertificate;
import com.solitardj9.authService.application.caCertMngt.service.CaCertManager;
import com.solitardj9.authService.utils.security.CertificateInfo;
import com.solitardj9.authService.utils.security.CertificateUtil;


@Service("caCertManager")
public class CaCertManagerImpl implements CaCertManager {
    //
	private static final Logger logger = LoggerFactory.getLogger(CaCertManagerImpl.class);
	
	@Value("${ca.certificate.issuer}")
	private String issuer;
	
	@Value("${ca.certificate.subject}")
	private String subject;
	
	@Value("${ca.certificate.duration}")
	private Long duration;
	
	@Value("${ca.certificate.signatureAlgorithm}")
	private String signatureAlgorithm;
	
	@Value("${ca.privateKey.algorithm}")
	private String algorithm;
	
	private CaCertificate caCertificate;
	
	private static final Integer KEY_LENGTH = 2048;
	
	private static String strCaCertificate = null;
	
	private static String strPrivateKey = null;
	
	private static String strPublicKey = null;
	
	@PostConstruct
	private void init() {
    	//
		Provider bc = new BouncyCastleProvider();
		Security.insertProviderAt(bc, 1);
		
    	try {
    		// CA 생성
    		this.caCertificate = createCaCertificate();
    		if (this.caCertificate != null) {
	    		saveFile(this.caCertificate);
	    		logger.info("caCertificate : \r\n" + this.caCertificate.toString());
    		}
    	} catch (Exception e) {
    		logger.error(e.toString());
    	}
    }
	
	@Override
	public CaCertificate getCaCertificate() {
		//
		return this.caCertificate;
	}
	
	@Override
	public Boolean updateCaCertificate(String certificate, String publicKey, String privateKey) {
		//
		try {
    		// CA 생성
			this.caCertificate = updateCaCertificateWithPem(certificate, publicKey, privateKey);
			if (this.caCertificate != null) {
	    		saveFile(this.caCertificate);
	    		logger.info("caCertificate : \r\n" + this.caCertificate.toString());
	    		return true;
    		}
    	} catch (Exception e) {
    		logger.error(e.toString());
    		return false;
    	}
		return false;
	}
	
	private CaCertificate updateCaCertificateWithPem(String caCertificatePem, String publicKeyPem, String privateKeyPem) {
		//
		CaCertificate caCertificate = null;
		
		try {
			X509Certificate x509Certificate = CertificateUtil.readX509Certificate(caCertificatePem);
			
			PublicKey publicKey = CertificateUtil.readPublicKey(publicKeyPem, algorithm);
			
			PrivateKey privateKey = CertificateUtil.readPrivateKey(privateKeyPem, algorithm);
			
			caCertificate = new CaCertificate(x509Certificate, publicKey, privateKey);
		} catch (Exception e) {
			logger.error(e.toString());
			return caCertificate;
		}
		
		return caCertificate;
	}
	
	private CaCertificate createCaCertificate() throws Exception {
		//
		CaCertificate caCertificate = null;
    	
		try {
	    	if (strCaCertificate == null || strCaCertificate.isEmpty()) {
	    		// 1) create keyPair
	    		KeyPair keyPair = CertificateUtil.generateKeyPair(algorithm, KEY_LENGTH);		// configure Key SPEC.
	    		
	    		// 2) create CA Certificate Info and check validation  
	    		CertificateInfo certificateInfo = new CertificateInfo(duration, new X500Name(issuer), new X500Name(subject), BigInteger.valueOf((int)new SecureRandom().nextInt()), KeyUsage.keyCertSign, true);
	    		if (!checkCertificateInfo(certificateInfo)) {
	    			logger.error("certificateInfo is not valid.");
	    			return null;
	    		}
	    		
	    		// 3) create Expired Date
	    		LocalDate now = LocalDate.now();
	    		Date createdDate = Date.valueOf(now);													// start of validity
	    		Date expiredDate = Date.valueOf(now.plusYears(certificateInfo.getValidDuration()));		// end of validity
	    		
	    		// 4) create CA Certificate
	    		X509Certificate x509Certificate = CertificateUtil.generateX509Certificate(certificateInfo, keyPair, createdDate, expiredDate, signatureAlgorithm);
	          
	    		// 5) make CA Certificate Instance
	    		caCertificate = new CaCertificate(x509Certificate, keyPair.getPublic(), keyPair.getPrivate());
	        }
	    	else {
	    		caCertificate = new CaCertificate();
	    		
	    		X509Certificate x509Certificate = CertificateUtil.readX509Certificate(strCaCertificate);
	    		if (x509Certificate != null) {
	    			caCertificate.setCaCertificate(x509Certificate);
	    		}
	    		
	    		PublicKey publicKey = CertificateUtil.readPublicKey(strPublicKey, algorithm);
	    		if (publicKey != null) {
	    			caCertificate.setPublicKey(publicKey);
	    		}
	    		
	    		PrivateKey privateKey = CertificateUtil.readPrivateKey(strPrivateKey, algorithm);
	    		if (privateKey != null) {
	    			caCertificate.setPrivateKey(privateKey);
	    		}
	    	}
		} catch (Exception e) {
			logger.error(e.toString());
			return caCertificate;
		}
    	
    	return caCertificate;
    }
	
	private void saveFile(CaCertificate caCertificate) {
		//
		if (caCertificate == null) {
			logger.error("caCertificate is null.");
			return;
		}
		
		// 1) X509Certificate --> pem(String)
		// 2) KeyPair(Public Key) --> pem(String )
		// 3) KeyPair(Private Key) --> pem(String )
		String pemCertificate = null;
		String pemPublicKey = null;
		String pemPrivateKey = null;
		try {
			pemCertificate = CertificateUtil.makeX509CertificateAsPem(caCertificate.getCaCertificate());
			pemPublicKey = CertificateUtil.publicKeyAsPem(caCertificate.getPublicKey());
			pemPrivateKey = CertificateUtil.privateKeyAsPem(caCertificate.getPrivateKey());
		} catch (CertificateEncodingException | IOException e) {
			logger.error(e.toString());
			return;
		}
		
		// 3) save File
		FileOutputStream fileOutputStream = null;
		try {
			fileOutputStream = new FileOutputStream("thingCACert.pem");
			fileOutputStream.write(pemCertificate.getBytes(Charset.forName("UTF-8")));
			fileOutputStream.flush();
			fileOutputStream.close();
		} catch (IOException e) {
			logger.error(e.toString());
			return;
		} finally {
			if (fileOutputStream != null) {
				try {
					fileOutputStream.close();
				} catch (IOException e) {
					logger.error(e.toString());
					return;
				}
			}
		}
		
		try {
			fileOutputStream = new FileOutputStream("thingCAPbKey.pem");
			fileOutputStream.write(pemPublicKey.getBytes(Charset.forName("UTF-8")));
			fileOutputStream.flush();
			fileOutputStream.close();
		} catch (IOException e) {
			logger.error(e.toString());
			return;
		} finally {
			if (fileOutputStream != null) {
				try {
					fileOutputStream.close();
				} catch (IOException e) {
					logger.error(e.toString());
					return;
				}
			}
		}
		
		try {
			fileOutputStream = new FileOutputStream("thingCAPvKey.pem");
			fileOutputStream.write(pemPrivateKey.getBytes(Charset.forName("UTF-8")));
			fileOutputStream.flush();
			fileOutputStream.close();
		} catch (IOException e) {
			logger.error(e.toString());
			return;
		} finally {
			if (fileOutputStream != null) {
				try {
					fileOutputStream.close();
				} catch (IOException e) {
					logger.error(e.toString());
					return;
				}
			}
		}
	}
	
	private Boolean checkCertificateInfo(CertificateInfo certificateInfo) {
		//
		if (certificateInfo.getIssuerName() == null) {
			logger.error("Issuer's information is nothing!");
			return false;
		}
		
		if (certificateInfo.getSubjectName() == null) {
			logger.error("Subject's information is nothing!");
			return false;
		}
		
		if (certificateInfo.getKeyUsage() != KeyUsage.keyCertSign) {
			logger.error("keyUsage is wrong!");
			certificateInfo.setKeyUsage(KeyUsage.keyCertSign);
			return false;
		}
		
		if (!certificateInfo.getBasicConstratints()) {
			logger.error("BasicConstratint must be true!");
			certificateInfo.setBasicConstratints(true);
			return false;
		}
		
		if (certificateInfo.getValidDuration() < 0 ) {
			logger.error("ValidDuration is wrong!");
			return false;
		}
		
		return true;
	}
}