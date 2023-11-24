#include <stdio.h>
#include <string.h>
#include "../include/crypto.h"

#define MAX_FILE_SIZE 1024

int main(int argc, char *argv[]) {

    const char *inputFileName = "../data/t1.txt";  // 세미콜론 추가

    const char *publicKeyFileName = "../wallet/public.pem";
    const char *privateKeyFileName = "../wallet/private.pem";

    const char *encryptedFileName = "../data/encrypted.bin";
    const char *decryptedFileName = "../data/decrypted.txt";

    if (strcmp(argv[1], "enc") == 0) {  // 문자열 비교 수정, 암호화
        encryptFile(inputFileName, publicKeyFileName, encryptedFileName);
        printf("File encrypted successfully.\n");
    }
    if (strcmp(argv[1], "dec") == 0) {  // 문자열 비교 수정, 복호화
        decryptFile(encryptedFileName, privateKeyFileName, decryptedFileName);
        printf("File decrypted successfully.\n");
    }

    return 0;
}
//gcc main.c ../bin/crypto.c -o colosus -lssl -lcrypto