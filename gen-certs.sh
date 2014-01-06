# These commands apparently generate x509v1 certs, which can be seen with:
#     openssl x509 -in certs/ca.crt -text
#
# x509v1 has no provisions for distinguising CA certs from End-Entity certs.
# I think this implies that you can sign certs with certs signed by the
# "acting CA cert". This is potentially problematic as a compromised leaf cert
# could be used to sign certs we otherwise don't want to trust. The workaround
# to that is to only trust certs signed by the "acting CA cert" and that don't
# have any intermediate certs in their chain. Alternatively x509v3 PKIX has a
# more robust specification for this.

# My guestimate on how v3 extensions works is that the CA issues certs
# containing the appropriate extensions (e.g. with CA:true when creating
# intermediate CA certs and CA:false when creating end-entity certs). Since it
# issues the certs, the CA has control over the privileges granted. Clients are
# responsible for verifying there are no violations of the extensions?
# Fundamentally, you could sign a new cert with an end-entity cert which has
# CA:false, but no client will accept such cert as the chain would be invalid
# (only leaf certs may have CA:false, all others must have CA:true)?

# Looking at a few websites, it seems that there are some intermediate CA v3
# certs signed by v1 root certs (though not all roots are v1).

# Note: my terminology is probably wrong as is my understanding of PKI. Don't
# rely on anything I've said here.


mkdir certs
chmod 700 certs

# Create a CA cert so we can sign other certs (technically you can sign without a CA cert, but verification doesn't work?)
openssl genrsa -out certs/ca.pem 2048
openssl req -new -key certs/ca.pem -out certs/ca.csr -subj "/C=US/ST=CA/L=SM/O=Laazy/CN=mycertauth"
openssl x509 -req -days 3650 -in certs/ca.csr -signkey certs/ca.pem -out certs/ca.crt

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
