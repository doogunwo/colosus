#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include "../include/crypto.h"
#define BUFFER_SIZE 1024

void handleErrors(void) {
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
}

void encryptFile(const char *inputFileName, const char *publicKeyFileName, const char *outputFileName) {
    FILE *inputFile = fopen(inputFileName, "rb");
    if (!inputFile) {
        perror("Error opening input file");
        exit(EXIT_FAILURE);
    }

    FILE *publicKeyFile = fopen(publicKeyFileName, "rb");
    if (!publicKeyFile) {
        perror("Error opening public key file");
        fclose(inputFile);
        exit(EXIT_FAILURE);
    }

    FILE *outputFile = fopen(outputFileName, "wb");
    if (!outputFile) {
        perror("Error opening output file");
        fclose(inputFile);
        fclose(publicKeyFile);
        exit(EXIT_FAILURE);
    }

    BIO *publicKeyBio = BIO_new_file(publicKeyFileName, "rb");
    if (!publicKeyBio) {
        perror("Error creating BIO for public key");
        fclose(inputFile);
        fclose(publicKeyFile);
        fclose(outputFile);
        exit(EXIT_FAILURE);
    }

    RSA *publicKey = PEM_read_bio_RSAPublicKey(publicKeyBio, NULL, NULL, NULL);
    BIO_free(publicKeyBio);
     if (!publicKey) {
        fprintf(stderr, "Error reading public key: PEM_read_bio_RSAPublicKey failed\n");
        fclose(inputFile);
        fclose(publicKeyFile);
        fclose(outputFile);
        exit(EXIT_FAILURE);
    }



    int keySize = RSA_size(publicKey);
    unsigned char *inputBuffer = (unsigned char *)malloc(BUFFER_SIZE);
    unsigned char *outputBuffer = (unsigned char *)malloc(keySize);

    size_t bytesRead;
    while ((bytesRead = fread(inputBuffer, 1, BUFFER_SIZE, inputFile)) > 0) {
        if (bytesRead < BUFFER_SIZE) {
            int paddedSize = RSA_public_encrypt(bytesRead, inputBuffer, outputBuffer, publicKey, RSA_PKCS1_PADDING);
            if (paddedSize < 0) {
                handleErrors();
            }
            fwrite(outputBuffer, 1, paddedSize, outputFile);
        } else {
            if (RSA_public_encrypt(BUFFER_SIZE, inputBuffer, outputBuffer, publicKey, RSA_PKCS1_PADDING) < 0) {
                handleErrors();
            }
            fwrite(outputBuffer, 1, keySize, outputFile);
        }
        printf("%.*s\n", (int)bytesRead, outputBuffer);
    }

    fclose(inputFile);
    fclose(publicKeyFile);
    fclose(outputFile);
    RSA_free(publicKey);
    free(inputBuffer);
    free(outputBuffer);
}

void decryptFile(const char *inputFileName, const char *privateKeyFileName, const char *outputFileName) {
    FILE *inputFile = fopen(inputFileName, "rb");
    if (!inputFile) {
        perror("Error opening input file");
        exit(EXIT_FAILURE);
    }

    FILE *privateKeyFile = fopen(privateKeyFileName, "rb");
    if (!privateKeyFile) {
        perror("Error opening private key file");
        fclose(inputFile);
        exit(EXIT_FAILURE);
    }

    FILE *outputFile = fopen(outputFileName, "wb");
    if (!outputFile) {
        perror("Error opening output file");
        fclose(inputFile);
        fclose(privateKeyFile);
        exit(EXIT_FAILURE);
    }
    //PEM_read_bio_RSAPrivateKey
    BIO *privateKeyBio = BIO_new_file(privateKeyFileName, "rb");
    if (!privateKeyBio) {
        perror("Error creating BIO for private key");
        fclose(inputFile);
        fclose(privateKeyFile);
        fclose(outputFile);
        exit(EXIT_FAILURE);
    }

    RSA *privateKey = PEM_read_bio_RSAPrivateKey(privateKeyBio, NULL, NULL, NULL);
    BIO_free(privateKeyBio);

    if (!privateKey) {
        fprintf(stderr, "Error reading private key: PEM_read_bio_RSAPrivateKey failed\n");
        fclose(inputFile);
        fclose(privateKeyFile);
        fclose(outputFile);
        exit(EXIT_FAILURE);
    }

  

    int keySize = RSA_size(privateKey);
    unsigned char *inputBuffer = (unsigned char *)malloc(keySize);
    unsigned char *outputBuffer = (unsigned char *)malloc(BUFFER_SIZE);

    size_t bytesRead;
    while ((bytesRead = fread(inputBuffer, 1, keySize, inputFile)) > 0) {
        int decryptedSize = RSA_private_decrypt(bytesRead, inputBuffer, outputBuffer, privateKey, RSA_PKCS1_PADDING);
        if (decryptedSize < 0) {
            handleErrors();
        }

        fwrite(outputBuffer, 1, decryptedSize, outputFile);
        printf("%.*s\n", (int)bytesRead, outputBuffer);
    }

    fclose(inputFile);
    fclose(privateKeyFile);
    fclose(outputFile);
    RSA_free(privateKey);
    free(inputBuffer);
    free(outputBuffer);
}

