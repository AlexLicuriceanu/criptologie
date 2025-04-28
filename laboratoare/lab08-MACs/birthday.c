#include <openssl/evp.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

/* We want a collision in the first 4 bytes = 2^16 attempts */
#define N_BITS 16
#define BUFLEN 10

int raw2int4(unsigned char *digest) {
    int i;
    int sum = 0;

    for (i = 0; i < 4; i++) {
        sum = (sum << 8) | digest[i];
    }

    return sum;
}

void hexdump(unsigned char *string, int length) {
    int i;

    for (i = 0; i < length; i++) {
        printf("%02x", string[i]);
    }
    printf("\n");
}

int main(int argc, char * argv[]) {
    //uint32_t attempt;                   /* Iterate through 16 bits of the 32; use the rest to run different attacks */
    EVP_MD_CTX *mdctx;                  /* Message digest context */
    unsigned char md[EVP_MAX_MD_SIZE];  /* SHA-1 outputs 160-bit digests */
    unsigned int md_len;                /* Length of the hash */
    unsigned char messages[1 << N_BITS][BUFLEN]; /* Array to store 2^16 random messages */
    int hashes[1 << N_BITS];            /* Array to store the first 4 bytes of each hash */

    /* Initialize random number generator */
    srand((unsigned int)time(NULL));

    while (1) {
        /* Step 1. Generate 2^16 different random messages */
        for (int i = 0; i < (1 << N_BITS); i++) {
            for (int j = 0; j < BUFLEN; j++) {
                messages[i][j] = rand() % 256;
            }
        }

        /* Step 2. Compute hashes */
        for (int i = 0; i < (1 << N_BITS); i++) {
            mdctx = EVP_MD_CTX_new();
            EVP_DigestInit_ex(mdctx, EVP_sha1(), NULL);
            EVP_DigestUpdate(mdctx, messages[i], BUFLEN);
            EVP_DigestFinal_ex(mdctx, md, &md_len);
            EVP_MD_CTX_free(mdctx);

            hashes[i] = raw2int4(md);
        }

        /* Step 3. Check if there exist two hashes that match in the first four bytes */
        for (int i = 0; i < (1 << N_BITS); i++) {
            for (int j = i + 1; j < (1 << N_BITS); j++) {
                if (hashes[i] == hashes[j]) {

                    /* Step 3a. If a match is found, print the messages and hashes */
                    printf("Collision found!\n");
                    printf("Message 1: ");
                    hexdump(messages[i], BUFLEN);
                    printf("Message 2: ");
                    hexdump(messages[j], BUFLEN);
                    printf("Hash: %08x\n", hashes[i]);

                    return 0;
                }
            }
        }

        /* Step 3b. If no match is found, repeat the attack with a new set of random messages */
        printf("No collision found, retrying\n");
    }

    return 0;
}