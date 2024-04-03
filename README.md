# SimpleEncryptor
A simple app using OpenSSL to encrypt and decrypt files using a symmetric encryption algorithm.

## WARNING 
I am not a cryptographer and this might very well be very insecure.

## Compiling

### Prerequisites
- OpenSSL
- gcc

If you would like to give this small project a try, go ahead and clone it.

Compiling is as easy as running:

```bash
g++ main.cpp -o encryptor -lssl -lcrypto
```
