#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>

#include "common.h"

const char *INSTANCE = "client";

void run_client(const server_config_t *config,
                EVP_PKEY *key_pair, void *buf_pubkey, size_t buf_pubkey_len) {
    int client_sockfd = 0;
    struct sockaddr_in server_addr;
    socklen_t server_len;

    /* Create new socket */
    client_sockfd = socket(AF_INET, SOCK_STREAM, 0);
    CHECK(client_sockfd >= 0, "socket");

    /* Setup sockaddr_in struct */
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(config->ip);
    server_addr.sin_port = htons(config->port);

    /* Connect to server*/
    server_len = sizeof(server_addr);
    CHECK(connect(client_sockfd, (struct sockaddr *) &server_addr,
                  server_len) >= 0, "connect");
    log("Connected to port %d\n", config->port);

    /* Perform Diffie Hellman key exchange */
    diffie_hellman_exchange(client_sockfd, key_pair,
                            buf_pubkey, buf_pubkey_len);

    close(client_sockfd);
}

int main(int argc, char* argv[]) {
    server_config_t config = parse_args(argc, argv);
    EVP_PKEY *key_pair = NULL;
    EVP_PKEY *pkey = NULL;
    unsigned char buf_pubkey[KEY_LEN];

    setvbuf(stdout, NULL, _IONBF, 0);

    /* Generate DH key pair */
    if (!(key_pair = generate_dh_key_pair(config.dh_filename))) {
        fprintf(stderr, "Error generating key pair\n");
        exit(EXIT_FAILURE);
    }

    /* Put the key into a buffer with will be sent to the client */
    if (evp_pkey_to_bin(key_pair, buf_pubkey) < 0) {
        fprintf(stderr, "Error while writing the pub key to buffer\n");
        exit(EXIT_FAILURE);
    }

    /* Print the key */
    log("Our public key is: ");
    print_buf_hex(buf_pubkey, KEY_LEN);

    /* Run the server */
    run_client(&config, key_pair, buf_pubkey, KEY_LEN);

    EVP_PKEY_free(key_pair);
    EVP_PKEY_free(pkey);
    return 0;
}
