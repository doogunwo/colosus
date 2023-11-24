#include <stdio.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

int main() {
    RSA *keypair = RSA_new();
    BIGNUM *e = BN_new();
    BN_set_word(e, RSA_F4);  // RSA_F4는 65537

    RSA_generate_key_ex(keypair, 2048, e, NULL);

    // 나머지 코드는 이전 예제와 동일하게 사용 가능

    // 개인 키를 파일로 저장
    FILE *privateKeyFile = fopen("../wallet/private.pem", "wb");
    PEM_write_RSAPrivateKey(privateKeyFile, keypair, NULL, NULL, 0, NULL, NULL);
    fclose(privateKeyFile);

    // 공개 키를 파일로 저장
    FILE *publicKeyFile = fopen("../wallet/public.pem", "wb");
    PEM_write_RSAPublicKey(publicKeyFile, keypair);
    fclose(publicKeyFile);

    RSA_free(keypair);
    BN_free(e);

    printf("RSA 키 쌍이 성공적으로 생성되었습니다.\n");

    return 0;
}
