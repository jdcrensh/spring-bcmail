package com.jdcrensh.springframework.bcmail;

import java.security.KeyPair;
import java.security.cert.X509Certificate;

public interface CertificateHolder {
	KeyPair getKeyPair();

	X509Certificate getCertificate();
}
