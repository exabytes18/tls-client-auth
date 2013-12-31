mkdir certs
chmod 700 certs

# Create a CA cert so we can sign other certs (technically you can sign without a CA cert, but verification doesn't work?)
openssl genrsa -out certs/ca.pem 2048
openssl req -new -key certs/ca.pem -out certs/ca.csr -subj "/C=US/ST=CA/L=SM/O=Laazy/CN=mycertauth"
openssl x509 -req -days 3650 -in certs/ca.csr -signkey certs/ca.pem -out certs/ca.crt -extensions v3_ca

# Create a certificate signed by the ca for the server
openssl genrsa -out certs/server.pem 2048
openssl req -new -key certs/server.pem -out certs/server.csr -subj "/C=US/ST=CA/L=SM/O=Laazy/CN=server"
openssl x509 -req -days 365 -CAkey certs/ca.pem -CA certs/ca.crt -CAcreateserial -in certs/server.csr -out certs/server.crt

# Create a certificate signed by the ca for client1
openssl genrsa -out certs/client1.pem 2048
openssl req -new -key certs/client1.pem -out certs/client1.csr -subj "/C=US/ST=CA/L=SM/O=Laazy/CN=client1"
openssl x509 -req -days 365 -CAkey certs/ca.pem -CA certs/ca.crt -CAcreateserial -in certs/client1.csr -out certs/client1.crt

# Create a self-signed certificate for client2
openssl genrsa -out certs/client2.pem 2048
openssl req -new -key certs/client2.pem -out certs/client2.csr -subj "/C=US/ST=CA/L=SM/O=Laazy/CN=client2"
openssl x509 -req -days 365 -in certs/client2.csr -signkey certs/client2.pem -out certs/client2.crt
