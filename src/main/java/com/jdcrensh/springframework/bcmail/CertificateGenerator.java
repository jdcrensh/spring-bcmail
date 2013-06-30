package com.jdcrensh.springframework.bcmail;

import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.X509Certificate;

public interface CertificateGenerator {
	KeyPair generateKeyPair() throws NoSuchProviderException, NoSuchAlgorithmException;

	X509Certificate buildCertificate(KeyPair subjectKeyPair, String subjectDN, KeyPair issuerKeyPair, String issuerDN);
}
