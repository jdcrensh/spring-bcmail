package com.jdcrensh.springframework.bcmail;

import java.io.IOException;
import java.io.InputStream;
import java.security.*;
import java.security.cert.X509Certificate;

import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;

public class CertificateHolderImpl implements CertificateHolder {

	private final String password;
	private final String alias;
	private final X509Certificate certificate;
	private final KeyStore keyStore;

	public CertificateHolderImpl(String path, String password, String alias) {
		this.password = password;
		this.alias = alias;
		try {
			Resource certResource = new FileSystemResource(path);
			InputStream inputStream = certResource.getInputStream();
			try {
				keyStore = KeyStore.getInstance("PKCS12");
				keyStore.load(inputStream, password.toCharArray());
				certificate = (X509Certificate) keyStore.getCertificate(alias);
			} catch (GeneralSecurityException e) {
				throw new RuntimeException(e);
			} finally {
				inputStream.close();
			}
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

	private PublicKey getPublicKey() {
		return certificate.getPublicKey();
	}

	private PrivateKey getPrivateKey() {
		PrivateKey privateKey;
		try {
			privateKey = (PrivateKey) keyStore.getKey(alias, password.toCharArray());
		} catch (GeneralSecurityException e) {
			throw new RuntimeException(e);
		}
		return privateKey;
	}

	@Override
	public KeyPair getKeyPair() {
		return new KeyPair(getPublicKey(), getPrivateKey());
	}

	@Override
	public X509Certificate getCertificate() {
		return certificate;
	}
}
