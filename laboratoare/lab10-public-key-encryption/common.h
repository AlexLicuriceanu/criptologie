#include <openssl/evp.h>
#include <openssl/err.h>
#include <stdlib.h>
#include <stdio.h>

#define KEY_LEN 256

#define CHECK(assertion, call_description)                                  \
    do {                                                                    \
        if (!(assertion)) {                                                 \
            fprintf(stderr, "(%s, %d): ",                                   \
                __FILE__, __LINE__);                                        \
            perror(call_description);                                       \
            exit(EXIT_FAILURE);                                             \
        }                                                                   \
    } while(0)

#define print_openssl_err(format, ...)                                      \
    fprintf(stderr, format ": %s\n",                                        \
            ##__VA_ARGS__, ERR_error_string(ERR_get_error(), NULL))

extern const char *INSTANCE;

#define log(format, ...)                                                    \
    printf("[%s]: " format, INSTANCE, ##__VA_ARGS__)

typedef struct server_config {
    char* ip;
    unsigned int port;
    char *dh_filename;
} server_config_t;

server_config_t parse_args(int argc, char* argv[]);

void receive_all(int sockfd, unsigned char *buffer, int length);

void print_buf_hex(const unsigned char *buffer, size_t buflen);

int evp_pkey_to_bin(EVP_PKEY *key_pair, unsigned char *buffer);

EVP_PKEY *generate_dh_key_pair(const char *filename);

void diffie_hellman_exchange(int connect_fd, EVP_PKEY *key_pair,
                             void* buf_pubkey, size_t buf_pubkey_len);
