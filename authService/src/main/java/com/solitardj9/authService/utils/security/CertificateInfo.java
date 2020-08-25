package com.solitardj9.authService.utils.security;

import java.math.BigInteger;

import org.bouncycastle.asn1.x500.X500Name;

public class CertificateInfo {
	//
	private Long			validDuration;							// expire duration(year)
	private X500Name		issuerName;								// issuer name
	private X500Name		subjectName;							// target name
	private BigInteger		serialNumber;							// serial number
	
	// extensionV3 
	private int				keyUsage;								// usage of key
	private boolean			basicConstratints;						// whether sub-certificate can be generated
	
	public CertificateInfo() {
	}
	
	public CertificateInfo(Long validDuration, X500Name issuerName, X500Name subjectName, int keyUsage, boolean basicConstratints) {
		this.validDuration = validDuration;
		this.issuerName = issuerName;
		this.subjectName = subjectName;
		this.keyUsage = keyUsage;
		this.basicConstratints = basicConstratints;
	}
	
	public CertificateInfo(Long validDuration, X500Name issuerName, X500Name subjectName, BigInteger  serialNumber, int keyUsage, boolean basicConstratints) {
		this.validDuration = validDuration;
		this.issuerName = issuerName;
		this.subjectName = subjectName;
		this.serialNumber = serialNumber;
		this.keyUsage = keyUsage;
		this.basicConstratints = basicConstratints;
	}
	
	public CertificateInfo(Long validDuration, int keyUsage, boolean basicConstratints) {
		this.validDuration = validDuration;
		this.keyUsage = keyUsage;
		this.basicConstratints = basicConstratints;
	}
	
	public CertificateInfo(Long validDuration, BigInteger  serialNumber, int keyUsage, boolean basicConstratints) {
		this.validDuration = validDuration;
		this.serialNumber = serialNumber;
		this.keyUsage = keyUsage;
		this.basicConstratints = basicConstratints;
	}

	public BigInteger getSerialNumber() {
		return serialNumber;
	}
	
	public void setSerialNumber(BigInteger serialNumber) {
		this.serialNumber = serialNumber;
	}
	
	public Long getValidDuration() {
		return validDuration;
	}

	public void setValidDuration(Long validDuration) {
		this.validDuration = validDuration;
	}

	public X500Name getIssuerName() {
		return issuerName;
	}
	
	public void setIssuerName(X500Name issuerName) {
		this.issuerName = issuerName;
	}
	
	public X500Name getSubjectName() {
		return subjectName;
	}
	
	public void setSubjectName(X500Name subjectName) {
		this.subjectName = subjectName;
	}
	
	public int getKeyUsage() {
		return keyUsage;
	}
	
	public void setKeyUsage(int keyUsage) {
		this.keyUsage = keyUsage;
	}
	
	public boolean getBasicConstratints() {
		return basicConstratints;
	}
	
	public void setBasicConstratints(boolean basicConstratints) {
		this.basicConstratints = basicConstratints;
	}
}