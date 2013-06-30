package com.jdcrensh.springframework.bcmail;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
public class CertificateGeneratorImpl implements CertificateGenerator {

	private Provider provider;
	private KeyPairGenerator kpg;

	private int serialNo = 1;

	@Autowired
	public CertificateGeneratorImpl(Provider provider) {
		ProviderUtil.ensureInstalled(provider);
		this.provider = provider;
		try {
			kpg = KeyPairGenerator.getInstance(ProviderUtil.ALGORITHM, provider);
		} catch (GeneralSecurityException e) {
			throw new RuntimeException(e);
		}
	}

	@Override
	public KeyPair generateKeyPair() {
		return kpg.generateKeyPair();
	}

	public AuthorityKeyIdentifier createAuthorityKeyId(PublicKey pub) {
		ByteArrayInputStream bIn = new ByteArrayInputStream(pub.getEncoded());
		SubjectPublicKeyInfo info = new SubjectPublicKeyInfo(asn1Sequence(bIn));
		return new AuthorityKeyIdentifier(info);
	}

	private ASN1Sequence asn1Sequence(ByteArrayInputStream bIn) {
		try {
			return (ASN1Sequence) new ASN1InputStream(bIn).readObject();
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

	public SubjectKeyIdentifier createSubjectKeyId(PublicKey pub) {
		ByteArrayInputStream bIn = new ByteArrayInputStream(pub.getEncoded());
		SubjectPublicKeyInfo info = new SubjectPublicKeyInfo(asn1Sequence(bIn));
		return new SubjectKeyIdentifier(info);
	}

	private ContentSigner contentSigner(PrivateKey issPriv) {
		try {
			return signerBuilder().build(issPriv);
		} catch (OperatorCreationException e) {
			throw new RuntimeException(e);
		}
	}

	private JcaContentSignerBuilder signerBuilder() {
		return new JcaContentSignerBuilder(ProviderUtil.SIGNATURE_ALGORITHM).setProvider(provider);
	}

	private X509Certificate extractCertificateHolder(X509CertificateHolder certHolder) {
		JcaX509CertificateConverter converter = new JcaX509CertificateConverter().setProvider(provider);
		try {
			return converter.getCertificate(certHolder);
		} catch (CertificateException e) {
			throw new RuntimeException(e);
		}
	}

	@Override
	public X509Certificate buildCertificate(KeyPair subjectKeyPair, String subjectDN, KeyPair issuerKeyPair, String issuerDN) {
		PublicKey subPub = subjectKeyPair.getPublic();
		PrivateKey issPriv = issuerKeyPair.getPrivate();
		PublicKey issPub = issuerKeyPair.getPublic();

		X509v3CertificateBuilder v3CertGen = new JcaX509v3CertificateBuilder(
				new X500Name(issuerDN), BigInteger.valueOf(serialNo++),
				new Date(System.currentTimeMillis()),
				new Date(System.currentTimeMillis() + (1000L * 60 * 60 * 24 * 100)),
				new X500Name(subjectDN), subPub
		);
		v3CertGen.addExtension(X509Extension.subjectKeyIdentifier, false, createSubjectKeyId(subPub));
		v3CertGen.addExtension(X509Extension.authorityKeyIdentifier, false, createAuthorityKeyId(issPub));

		ContentSigner contentSigner = contentSigner(issPriv);
		X509CertificateHolder certHolder = v3CertGen.build(contentSigner);
		return extractCertificateHolder(certHolder);
	}
}
