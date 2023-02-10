This directory includes the samples of certificates with keys. `test.crt` is the server certificate. `test.key` is its secret key. Both are embeded into the module binary.

`root.crt` is the root certificate, which clients need.

These files are enough for testing but if you try to generete your own, read the followings.

## How to generate self-signed certificate with a custom root CA

Generate a private key for a root CA.
```
openssl ecparam -out root.key -name prime256v1 -genkey
```

Generate a Certificate Signing Request (CSR).
```
openssl req -new -sha256 -key root.key -out root.csr
```

Generate a root certificate.
```
openssl x509 -req -sha256 -days 365 -in root.csr -signkey root.key -out root.crt
```

Generate a private key (`DER` format) for a server certificate.
```
openssl ecparam -out test.key -name prime256v1 -genkey -outform DER
```

Generate a CSR.
```
openssl req -new -sha256 -key test.key -out test.csr
```

Generate the server certificate (`DER` format) with the CSR and the key and sign it with the CA's root key. Update `subject.txt' for your server host name if necessary.
```
openssl x509 -req -in test.csr -CA  root.crt -CAkey root.key -CAcreateserial -out test.crt -days 365 -sha256 -extfile subject.txt -outform DER
```
