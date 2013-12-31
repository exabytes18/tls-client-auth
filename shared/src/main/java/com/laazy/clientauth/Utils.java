package com.laazy.clientauth;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMReader;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.Collection;

public class Utils {
	static {
		if (Security.getProvider("BC") == null) {
			Security.addProvider(new BouncyCastleProvider());
		}
	}

	private Utils() {
	}

	public static KeyManager[] createKeyManagers(String keyFile, String certificatesFile) throws
	UnrecoverableKeyException,
	NoSuchAlgorithmException,
	KeyStoreException,
	IOException,
	CertificateException {
		KeyStore ks = KeyStore.getInstance("JKS");
		ks.load(null, null);
		Object pemObject = new PEMReader(new FileReader(keyFile)).readObject();
		final Key key;
		if (pemObject instanceof KeyPair) {
			key = ((KeyPair) pemObject).getPrivate();
		} else if (pemObject instanceof PrivateKey) {
			key = (Key) pemObject;
		} else {
			throw new IllegalArgumentException("Unknown input: " + pemObject.getClass());
		}

		Collection<? extends java.security.cert.Certificate> certificates = CertificateFactory.getInstance("X.509")
				.generateCertificates(new FileInputStream(certificatesFile));
		ks.setKeyEntry("my-key", key, new char[0],
				certificates.toArray(new java.security.cert.Certificate[certificates.size()]));

		KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
		kmf.init(ks, new char[0]);
		return kmf.getKeyManagers();
	}

	public static TrustManager[] createTrustManagers(String certificatesFile) throws
	NoSuchAlgorithmException,
	KeyStoreException,
	IOException,
	CertificateException {
		KeyStore ks = KeyStore.getInstance("JKS");
		ks.load(null, null);

		int num = 0;
		Collection<? extends java.security.cert.Certificate> certificates = CertificateFactory.getInstance("X.509")
				.generateCertificates(new FileInputStream(certificatesFile));
		for (java.security.cert.Certificate certificate : certificates) {
			ks.setCertificateEntry("my-cert-" + (num++), certificate);
		}

		TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
		tmf.init(ks);

		return tmf.getTrustManagers();
	}
}
