#include <openssl/evp.h>
#include <openssl/err.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define TAG_LEN 16

void hexdump(unsigned char * string, int length) {
    int i;
    for (i = 0; i < length; i++) {
        printf("%02x", string[i]);
    }
}

int aes_gcm_encrypt(unsigned char * ptext,
        int plen,
        unsigned char * key,
        unsigned char * iv,
        unsigned char ** ctext,
        int * clen) {

    EVP_CIPHER_CTX * ctx;

    /* TODO Create new EVP Context */
    ctx = EVP_CIPHER_CTX_new();

    if (!ctx) {
        return -1;
    }

    int len, ciphertext_len;

    /* TODO Initialize context using 256-bit AES-GCM, Encryption operation */
    if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) {
        return -1;
    }

    /* TODO Initialize Key and IV for the new context */
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL)) {
        return -1;
    }

    if (!EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv)) {
        return -1;
    }

    *ctext = malloc(plen + TAG_LEN);
    if (!*ctext) {
        return -1;
    }

    /* TODO Encrypt data */
    if (!EVP_EncryptUpdate(ctx, *ctext, &len, ptext, plen)) {
        return -1;
    }

    ciphertext_len = len;

    /* TODO Finalize encryption context (computes and appends auth tag) */
    if (!EVP_EncryptFinal_ex(ctx, *ctext + len, &len)) {
        return -1;
    }

    ciphertext_len += len;

    unsigned char tag[TAG_LEN];
    
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag)) {
        return -1;
    }

    memcpy(*ctext + ciphertext_len, tag, TAG_LEN);
    *clen = ciphertext_len + TAG_LEN;

    /* TODO Print tag */
    printf("Auth tag = "); hexdump(tag, TAG_LEN); printf("\n");

    /* TODO Destroy context */
    EVP_CIPHER_CTX_free(ctx);

    return 0;
}

int aes_gcm_decrypt(unsigned char * ctext,
        int clen,
        unsigned char * key,
        unsigned char * iv,
        unsigned char ** ptext,
        int * plen) {

    EVP_CIPHER_CTX * ctx;

    /* TODO Create new EVP Context */
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return -1;
    }

    int len, plaintext_len;
    int ciphertext_len = clen - TAG_LEN;
    unsigned char * tag = ctext + ciphertext_len;

    *ptext = malloc(ciphertext_len);

    if (!*ptext) {
        return -1;
    }

    /* TODO Initialize context using 256-bit AES-GCM, Decryption operation */
    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) {
        return -1;
    }

    /* TODO Initialize Key and IV for the new context */
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL)) {
        return -1;
    }

    if (!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv)) {
        return -1;
    }

    /* TODO Submit tag data */
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, tag)) {
        return -1;
    }

    /* TODO Decrypt data */
    if (!EVP_DecryptUpdate(ctx, *ptext, &len, ctext, ciphertext_len)) {
        return -1;
    }

    plaintext_len = len;

    /* TODO Finalize decryption context (verifies auth tag) */
    if (EVP_DecryptFinal_ex(ctx, *ptext + len, &len) <= 0) {
        free(*ptext);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    plaintext_len += len;
    *plen = plaintext_len;

    /* TODO Destroy context */
    EVP_CIPHER_CTX_free(ctx);

    return 0;
}

int main(int argc, char * argv[]) {
    ERR_load_crypto_strings();

    unsigned char key[] = "0123456789abcdef0123456789abcdef"; /* 256-bit key */
    unsigned char iv[] = "0123456789ab";                      /* 96-bit IV   */

    unsigned char * ptext = (unsigned char *)"Hello, SSLWorld!\n";
    int plen = strlen((const char *)ptext);

    unsigned char * ctext;
    int clen;

    printf("Plaintext = %s\n", ptext);
    printf("Plaintext  (hex) = "); hexdump(ptext, plen); printf("\n");

    aes_gcm_encrypt(ptext, plen, key, iv, &ctext, &clen);
    printf("Ciphertext (hex) = "); hexdump(ctext, clen - TAG_LEN); printf("\n");

    unsigned char * ptext2;
    int plen2;
    if (aes_gcm_decrypt(ctext, clen, key, iv, &ptext2, &plen2) != 0) {
        printf("Decryption failed!\n");
        free(ctext);
        return 1;
    }
    printf("Done decrypting!\n");

    ptext2[plen2] = '\0';
    printf("Plaintext = %s\n", ptext2);

    if (memcmp(ptext, ptext2, strlen((const char *)ptext)) == 0) {
        printf("Ok!\n");
    } else {
        printf("Not ok :(\n");
    }

    free(ctext);
    free(ptext2);
    return 0;
}
