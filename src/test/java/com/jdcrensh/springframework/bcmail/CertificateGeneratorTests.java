package com.jdcrensh.springframework.bcmail;

import java.security.KeyPair;
import java.security.cert.X509Certificate;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Before;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import static org.junit.Assert.assertEquals;

public class CertificateGeneratorTests {
	private static final Logger log = LoggerFactory.getLogger(CertificateGeneratorTests.class);

	CertificateGenerator generator;

	@Before
	public void setUp() throws Exception {
		generator = new CertificateGeneratorImpl(new BouncyCastleProvider());
	}

	@Test
	public void testGenerate() throws Exception {
		KeyPair sub = generator.generateKeyPair();
		KeyPair iss = generator.generateKeyPair();
		X509Certificate certificate = generator.buildCertificate(sub, "CN=subDN", iss, "CN=issDN");
		assertEquals("CN=subDN", certificate.getSubjectDN().getName());
		assertEquals("CN=issDN", certificate.getIssuerDN().getName());
	}
}
