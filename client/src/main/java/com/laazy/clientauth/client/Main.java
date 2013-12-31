package com.laazy.clientauth.client;

import com.laazy.clientauth.Utils;
import org.apache.commons.io.IOUtils;

import javax.net.ssl.*;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

public class Main {
	private static final String HOSTNAME = "localhost";
	private static final int PORT = 8443;

	public static void main(String[] args) throws
	IOException,
	InterruptedException,
	NoSuchAlgorithmException,
	UnrecoverableKeyException,
	KeyStoreException,
	CertificateException,
	KeyManagementException {
		final TrustManager[] trustManagers;
		if (args.length >= 1) {
			trustManagers = Utils.createTrustManagers(args[0]);
		} else {
			trustManagers = null;
		}

		final KeyManager[] keyManagers;
		if (args.length == 3) {
			String keyFile = args[1];
			String certificatesFile = args[2];
			keyManagers = Utils.createKeyManagers(keyFile, certificatesFile);
		} else {
			keyManagers = null;
		}

		SSLContext sc = SSLContext.getInstance("TLSv1.2");
		sc.init(keyManagers, trustManagers, null);
		SSLSocketFactory socketFactory = sc.getSocketFactory();
		makeConnection(socketFactory);
	}

	private static void makeConnection(SSLSocketFactory ssocketFactory) throws IOException {
		SSLSocket socket = (SSLSocket) ssocketFactory.createSocket(HOSTNAME, PORT);

		socket.startHandshake(); // Synchronous for initial handshake

		try (InputStream in = socket.getInputStream(); OutputStream out = socket.getOutputStream()) {
			byte[] bytes = IOUtils.toByteArray(in);
			System.out.println(new String(bytes));
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
}
