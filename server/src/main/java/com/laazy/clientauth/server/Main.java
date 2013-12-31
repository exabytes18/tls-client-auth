package com.laazy.clientauth.server;

import com.laazy.clientauth.Utils;

import javax.net.ssl.*;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

/**
 * This is only a PoC...
 * <p/>
 * Also, I dislike file-based java keystores since they don't play well with others (importing keys+certs is
 * unnecessarily difficult), so we'll just assemble a keystore in memory.
 * <p/>
 * This runs on port 8443 and serves a simple HTTP response; it waits for no request. This is bare minimum functionality
 * needed to visibly confirm that the ssl connections are working as expected (can test with a browser as well as client
 * provided here).
 */
public class Main {
	private static final int PORT = 8443;

	public static void main(String[] args) throws
	IOException,
	KeyStoreException,
	CertificateException,
	NoSuchAlgorithmException,
	UnrecoverableKeyException,
	KeyManagementException {
		if (args.length != 3) {
			System.err.println("You must specify a ca.crt, server.key, server.crt.");
			System.exit(1);
		}

		String caCert = args[0];
		String keyFile = args[1];
		String certificatesFile = args[2];
		KeyManager[] keyManagers = Utils.createKeyManagers(keyFile, certificatesFile);

		// Don't use server's cert, use the ca cert
		TrustManager[] trustManagers = Utils.createTrustManagers(caCert);

		SSLContext sc = SSLContext.getInstance("TLSv1.2");
		sc.init(keyManagers, trustManagers, null);
		SSLServerSocketFactory serverSocketFactory = sc.getServerSocketFactory();
		SSLServerSocket serverSocket = (SSLServerSocket) serverSocketFactory.createServerSocket(PORT);
		serverSocket.setReuseAddress(true);
		serverSocket.setNeedClientAuth(true); // Yay, require client auth.

		while (true) {
			final SSLSocket socket = (SSLSocket) serverSocket.accept();

			try {
				socket.startHandshake(); // Synchronous for initial handshake

				SSLSession session = socket.getSession();
				System.out.println("Accepted ssl connection:");
				if (socket.getNeedClientAuth()) {
					System.out.println("  peer principle: " + session.getPeerPrincipal());
					Certificate[] peerCertificates = session.getPeerCertificates();
					for (Certificate peerCertificate : peerCertificates) {
						if (peerCertificate instanceof X509Certificate) {
							X509Certificate x509Certificate = (X509Certificate) peerCertificate;
							// Could we implement a revocation scheme based on serial number blacklist?
							System.out.println("  peer cert serial number: " + x509Certificate.getSerialNumber());
						}
					}
				}

				new Thread(new Runnable() {
					@Override
					public void run() {
						try (InputStream in = socket.getInputStream(); OutputStream out = socket.getOutputStream()) {
							out.write(("HTTP/1.1 200 OK\r\n" +
									"Content-Type: text/html; charset=UTF-8\r\n" +
									"Content-Length: 5\r\n\r\n" +
									"hello").getBytes());
							out.flush();
						} catch (IOException e) {
							e.printStackTrace();
						}
					}
				}).start();
			} catch (SSLHandshakeException e) {
				System.err.println("connection closed: " + e.getMessage());
			}
		}
	}
}
