#ifndef CRYPTO_H
#define CRYPTO_H

#include <openssl/rsa.h>

void handleErrors(void);
void encryptFile(const char *inputFileName, const char *publicKeyFileName, const char *outputFileName);
void decryptFile(const char *inputFileName, const char *privateKeyFileName, const char *outputFileName);

#endif  // CRYPTO_H
