#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>

#include "common.h"

const char *INSTANCE = "server";

static void run_server(const server_config_t *config, EVP_PKEY *key_pair,
                       void *buf_pubkey, size_t buf_pubkey_len) {
    int listen_fd = 0;
    int connect_fd = 0;
    struct sockaddr_in client_addr, server_addr;
    socklen_t client_len;

    /* Create new socket */
    listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    CHECK(listen_fd >= 0, "socket");

    /* Setup sockaddr_in struct */
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(config->ip);
    server_addr.sin_port = htons(config->port);

    /* Bind */
    CHECK(bind(listen_fd, (struct sockaddr *) &server_addr,
               sizeof(server_addr)) >= 0, "bind");

    /* Listen */
    CHECK(listen(listen_fd, 0) >= 0, "listen");

    log("Server listening on port %d...\n", config->port);

    /* Accept incoming connections */
    while (1) {
        client_len = sizeof(client_addr);
        connect_fd = accept(listen_fd, (struct sockaddr *) &client_addr,
                            &client_len);
        CHECK(connect_fd >= 0, "accept failed");

        /* Perform Diffie Hellman key exchange */
        diffie_hellman_exchange(connect_fd, key_pair,
                                buf_pubkey, buf_pubkey_len);

        close(connect_fd);
    }

    /* Won't ever run this */
    close(listen_fd);
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

    /* Put the key into a buffer with will be sent to the client*/
    if (evp_pkey_to_bin(key_pair, buf_pubkey) < 0) {
        fprintf(stderr, "Error while writing the pub key to buffer\n");
        exit(EXIT_FAILURE);
    }

    /* Print the key */
    log("Our public key is: ");
    print_buf_hex(buf_pubkey, KEY_LEN);

    /* Run the server */
    run_server(&config, key_pair, buf_pubkey, KEY_LEN);

    /* Won't ever run this */
    EVP_PKEY_free(key_pair);
    EVP_PKEY_free(pkey);
    return 0;
}
